"""ONEX Edge: one-click Cloudflare Worker relay in front of the panel.

The panel uploads ``worker/onex-edge.js`` to the admin's Cloudflare account,
enables its workers.dev route (and optionally a custom domain on a Cloudflare
zone) and then appends "☁️ Edge" copies of every WebSocket config to each
subscription. Those copies connect to Cloudflare, and the Worker forwards the
stream to the panel, so accounting/limits keep working unchanged.

Settings: DATA_DIR/cf_edge.json (contains the API token; never commit it).
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request

CF_API = "https://api.cloudflare.com/client/v4"
WORKER_FILE = Path(__file__).resolve().parents[2] / "worker" / "onex-edge.js"
TOKEN_HELP_URL = "https://dash.cloudflare.com/profile/api-tokens"
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^\[?[0-9a-fA-F:]+\]?$")

DEFAULTS = {
    "enabled": False,
    "account_id": "",
    "api_token": "",
    "script_name": "",
    "workers_dev_host": "",
    "custom_domain": "",
    "secret": "",
    "include_in_sub": True,
    "clean_ips": [],
    "deployed_at": "",
    "origin": "",
    "last_error": "",
}


def _m():
    for name in ("main", "__main__"):
        mod = sys.modules.get(name)
        if mod is not None and hasattr(mod, "LINKS"):
            return mod
    import main as mod  # noqa
    return mod


def _file() -> Path:
    return Path(_m().DATA_DIR) / "cf_edge.json"


def load() -> dict:
    try:
        data = json.loads(_file().read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {**DEFAULTS, **data}
    except Exception:
        pass
    return dict(DEFAULTS)


def save(data: dict) -> None:
    p = _file()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(p)
    try:
        p.chmod(0o600)
    except Exception:
        pass


def edge_host(cfg: dict | None = None) -> str:
    cfg = cfg or load()
    return (cfg.get("custom_domain") or cfg.get("workers_dev_host") or "").strip().lower()


def valid_edge_secret(value: str | None, cfg: dict | None = None) -> bool:
    """Validate the secret injected into requests by the managed Worker."""
    import hmac
    expected = str((cfg or load()).get("secret") or "").strip()
    received = str(value or "").strip()
    return bool(expected and received and hmac.compare_digest(received, expected))


def public_view(cfg: dict) -> dict:
    tok = cfg.get("api_token") or ""
    out = {k: v for k, v in cfg.items() if k not in ("api_token", "secret")}
    out["has_token"] = bool(tok)
    out["token_masked"] = (tok[:4] + "…" + tok[-4:]) if len(tok) > 10 else ("•••" if tok else "")
    out["edge_host"] = edge_host(cfg)
    out["token_help_url"] = TOKEN_HELP_URL
    return out


# ---------------------------------------------------------------- Cloudflare API

class CFError(Exception):
    pass


async def _cf(method: str, path: str, token: str, **kw):
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(timeout=httpx.Timeout(40, connect=15)) as c:
        r = await c.request(method, CF_API + path, headers=headers, **kw)
    try:
        data = r.json()
    except Exception:
        raise CFError(f"Cloudflare HTTP {r.status_code}")
    if not data.get("success", False):
        errs = data.get("errors") or []
        msg = "; ".join(f"{e.get('code')}: {e.get('message')}" for e in errs if isinstance(e, dict)) or f"HTTP {r.status_code}"
        raise CFError(msg)
    return data.get("result")


async def _resolve_account(token: str, account_id: str) -> str:
    if account_id:
        return account_id
    accounts = await _cf("GET", "/accounts", token, params={"per_page": 50}) or []
    if len(accounts) == 1:
        return accounts[0]["id"]
    if not accounts:
        raise CFError("هیچ اکانتی برای این توکن پیدا نشد؛ Account ID را دستی وارد کنید")
    raise CFError("توکن به چند اکانت دسترسی دارد؛ Account ID را دستی وارد کنید")


async def _ensure_subdomain(token: str, acc: str) -> str:
    try:
        res = await _cf("GET", f"/accounts/{acc}/workers/subdomain", token)
        sub = (res or {}).get("subdomain")
        if sub:
            return sub
    except CFError:
        pass
    want = "onex-" + secrets.token_hex(3)
    res = await _cf("PUT", f"/accounts/{acc}/workers/subdomain", token, json={"subdomain": want})
    return (res or {}).get("subdomain") or want


async def _zone_for(token: str, hostname: str) -> str:
    parts = hostname.split(".")
    for i in range(len(parts) - 1):
        cand = ".".join(parts[i:])
        res = await _cf("GET", "/zones", token, params={"name": cand}) or []
        if res:
            return res[0]["id"]
    raise CFError(f"دامنه {hostname} در این اکانت Cloudflare نیست")


async def deploy(cfg: dict, origin: str) -> dict:
    token = (cfg.get("api_token") or "").strip()
    if not token:
        raise CFError("API Token وارد نشده")
    if not origin or not _HOST_RE.match(origin):
        raise CFError("دامنه عمومی پنل پیدا نشد؛ پنل را یک‌بار از آدرس Railway باز کنید")
    if not WORKER_FILE.exists():
        raise CFError("فایل worker/onex-edge.js پیدا نشد")
    acc = await _resolve_account(token, (cfg.get("account_id") or "").strip())
    name = cfg.get("script_name") or ("onex-edge-" + secrets.token_hex(3))
    secret = cfg.get("secret") or secrets.token_urlsafe(24)
    metadata = {
        "main_module": "onex-edge.js",
        "compatibility_date": "2024-11-01",
        "bindings": [
            {"type": "plain_text", "name": "ORIGIN", "text": origin},
            {"type": "secret_text", "name": "KEY", "text": secret},
        ],
    }
    files = {
        "metadata": ("metadata.json", json.dumps(metadata), "application/json"),
        "onex-edge.js": ("onex-edge.js", WORKER_FILE.read_bytes(), "application/javascript+module"),
    }
    await _cf("PUT", f"/accounts/{acc}/workers/scripts/{name}", token, files=files)
    await _cf("POST", f"/accounts/{acc}/workers/scripts/{name}/subdomain", token,
              json={"enabled": True, "previews_enabled": False})
    sub = await _ensure_subdomain(token, acc)
    custom = (cfg.get("custom_domain") or "").strip().lower()
    if custom:
        if not _HOST_RE.match(custom):
            raise CFError("دامنه سفارشی نامعتبر است")
        zid = await _zone_for(token, custom)
        await _cf("PUT", f"/accounts/{acc}/workers/domains", token,
                  json={"environment": "production", "hostname": custom, "service": name, "zone_id": zid})
    cfg.update(
        enabled=True, account_id=acc, script_name=name, secret=secret, origin=origin,
        workers_dev_host=f"{name}.{sub}.workers.dev", deployed_at=datetime.now().isoformat(), last_error="",
    )
    return cfg


async def remove(cfg: dict) -> dict:
    token, acc, name = cfg.get("api_token"), cfg.get("account_id"), cfg.get("script_name")
    if token and acc and name:
        try:
            await _cf("DELETE", f"/accounts/{acc}/workers/scripts/{name}", token, params={"force": "true"})
        except CFError as exc:
            if "10007" not in str(exc):  # 10007 = script not found
                raise
    cfg.update(enabled=False, script_name="", workers_dev_host="", deployed_at="", secret="")
    return cfg


async def test(cfg: dict) -> dict:
    host = edge_host(cfg)
    if not host:
        raise CFError("Edge هنوز دیپلوی نشده")
    async with httpx.AsyncClient(timeout=15) as c:
        t0 = datetime.now()
        r = await c.get(f"https://{host}/__onex_ping")
        ms = int((datetime.now() - t0).total_seconds() * 1000)
    data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    return {"ok": r.status_code == 200 and data.get("edge") == "onex", "status": r.status_code, "ms": ms, "colo": data.get("colo", "")}


# ---------------------------------------------------------------- subscription variants

_TAG = " ☁️Edge"


def _rewrite_uri(uri: str, host: str, address: str, tag: str = _TAG) -> str | None:
    if uri.startswith("vmess://"):
        try:
            raw = uri[8:]
            obj = json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8"))
        except Exception:
            return None
        if str(obj.get("net")) != "ws":
            return None
        obj.update(add=address, port="443", host=host, sni=host, tls="tls", alpn="http/1.1",
                   ps=str(obj.get("ps") or "ONEX") + tag)
        return "vmess://" + base64.b64encode(json.dumps(obj, ensure_ascii=False).encode()).decode()
    if not (uri.startswith("vless://") or uri.startswith("trojan://")):
        return None
    parts = urlsplit(uri)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    if q.get("type") != "ws" or q.get("security") == "reality":
        return None
    user = parts.netloc.rsplit("@", 1)[0] if "@" in parts.netloc else ""
    if not user:
        return None
    addr = f"[{address}]" if ":" in address and not address.startswith("[") else address
    q.update(security="tls", sni=host, host=host, alpn="http/1.1")
    q.pop("pbk", None); q.pop("sid", None); q.pop("spx", None)
    name = unquote(parts.fragment or "ONEX") + tag
    return urlunsplit((parts.scheme, f"{user}@{addr}:443", parts.path, urlencode(q, safe="/,"), quote(name, safe="")))


def extra_uris(uris: list[str]) -> list[str]:
    cfg = load()
    if not cfg.get("enabled") or not cfg.get("include_in_sub"):
        return []
    host = edge_host(cfg)
    if not host:
        return []
    addresses = [a for a in (cfg.get("clean_ips") or []) if a][:5] or [host]
    out: list[str] = []
    for uri in uris:
        for i, addr in enumerate(addresses):
            new = _rewrite_uri(uri, host, addr, _TAG if len(addresses) == 1 else f"{_TAG}{i + 1}")
            if new:
                out.append(new)
    return out


# ---------------------------------------------------------------- panel API

def build_router(require_perm) -> APIRouter:
    r = APIRouter(prefix="/api/cfedge", tags=["cloudflare-edge"])
    dep = Depends(require_perm("settings"))

    def _clean_ips(raw) -> list[str]:
        items = raw if isinstance(raw, list) else re.split(r"[\s,]+", str(raw or ""))
        out = []
        for x in items:
            x = str(x).strip().lower()
            if x and (_IP_RE.match(x) or _HOST_RE.match(x)) and x not in out:
                out.append(x)
        return out[:5]

    @r.get("")
    async def get_cfg(_=dep):
        return public_view(load())

    @r.post("/settings")
    async def set_cfg(request: Request, _=dep):
        body = await request.json()
        cfg = load()
        if body.get("api_token"):
            cfg["api_token"] = str(body["api_token"]).strip()[:200]
        if "account_id" in body:
            acc = str(body.get("account_id") or "").strip()
            if acc and not re.fullmatch(r"[0-9a-f]{32}", acc):
                raise HTTPException(400, "Account ID باید ۳۲ کاراکتر hex باشد")
            cfg["account_id"] = acc
        if "custom_domain" in body:
            d = str(body.get("custom_domain") or "").strip().lower()
            if d and not _HOST_RE.match(d):
                raise HTTPException(400, "دامنه سفارشی نامعتبر است")
            cfg["custom_domain"] = d
        if "include_in_sub" in body:
            cfg["include_in_sub"] = bool(body.get("include_in_sub"))
        if "clean_ips" in body:
            cfg["clean_ips"] = _clean_ips(body.get("clean_ips"))
        save(cfg)
        return public_view(cfg)

    @r.post("/deploy")
    async def do_deploy(request: Request, _=dep):
        cfg = load()
        m = _m()
        origin = m.get_host(request)
        try:
            cfg = await deploy(cfg, origin)
        except (CFError, httpx.HTTPError) as exc:
            cfg["last_error"] = str(exc)
            save(cfg)
            raise HTTPException(400, f"Cloudflare: {exc}")
        save(cfg)
        try:
            m.log_activity("edge", f"Cloudflare Edge دیپلوی شد: {edge_host(cfg)}")
        except Exception:
            pass
        return public_view(cfg)

    @r.post("/remove")
    async def do_remove(_=dep):
        cfg = load()
        try:
            cfg = await remove(cfg)
        except (CFError, httpx.HTTPError) as exc:
            raise HTTPException(400, f"Cloudflare: {exc}")
        save(cfg)
        return public_view(cfg)

    @r.post("/toggle")
    async def do_toggle(request: Request, _=dep):
        body = await request.json()
        cfg = load()
        if body.get("enabled") and not cfg.get("script_name"):
            raise HTTPException(400, "اول Edge را دیپلوی کنید")
        cfg["enabled"] = bool(body.get("enabled"))
        save(cfg)
        return public_view(cfg)

    @r.post("/test")
    async def do_test(_=dep):
        try:
            return await test(load())
        except (CFError, httpx.HTTPError, ValueError) as exc:
            return {"ok": False, "error": str(exc)}

    return r
