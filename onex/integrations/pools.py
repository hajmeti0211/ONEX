"""ONEX managed IP and outbound proxy pools.

The pool stores operator-managed entries only. It never imports public proxy
lists automatically and never exposes proxy credentials in API responses.
"""
from __future__ import annotations
import asyncio, ipaddress, json, re, socket, ssl, time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit
from fastapi import APIRouter, Depends, HTTPException, Request

_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
_PROXY_SCHEMES = {"http", "https", "socks4", "socks5"}

def _m():
    import main
    return main

def _file():
    return Path(_m().DATA_DIR) / "onex_pools.json"

def _load():
    try:
        data = json.loads(_file().read_text(encoding="utf-8"))
        if isinstance(data, dict):
            data.setdefault("ips", []); data.setdefault("proxies", [])
            return data
    except Exception:
        pass
    return {"ips": [], "proxies": []}

def _save(data):
    p = _file(); p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp"); tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"); tmp.replace(p)
    try: p.chmod(0o600)
    except Exception: pass

def _id(prefix):
    import secrets
    return prefix + "_" + secrets.token_hex(5)

def _clean_host(v):
    x = str(v or "").strip().lower()
    try:
        ipaddress.ip_address(x); return x
    except ValueError:
        if _HOST_RE.fullmatch(x): return x
    raise HTTPException(400, "آدرس IP یا دامنه معتبر نیست")

def _split_host_port(value, default_port=443):
    """Parse host:port without breaking IPv6 literals."""
    raw = str(value or "").strip()
    if not raw:
        raise HTTPException(400, "آدرس خالی است")
    if raw.startswith("["):
        end = raw.find("]")
        if end < 0:
            raise HTTPException(400, "آدرس IPv6 نامعتبر است")
        host = raw[1:end]
        suffix = raw[end + 1:]
        port = int(suffix[1:]) if suffix.startswith(":") and suffix[2:] else default_port
    elif raw.count(":") == 1:
        host, port_text = raw.rsplit(":", 1)
        port = int(port_text) if port_text else default_port
    else:
        host, port = raw, default_port
    if not 1 <= int(port) <= 65535:
        raise HTTPException(400, "پورت باید بین ۱ تا ۶۵۵۳۵ باشد")
    return host.strip().lower(), int(port)

def _public_ip(row):
    return {k:v for k,v in row.items() if k not in {"username", "password"}}

def _public_proxy(row):
    out = dict(row); out.pop("username", None); out.pop("password", None)
    out["has_auth"] = bool(row.get("username") or row.get("password"))
    return out

async def _probe(host, port, timeout=3.0, tls=False):
    started=time.perf_counter(); writer=None
    try:
        ctx=None
        if tls:
            ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        _,writer=await asyncio.wait_for(asyncio.open_connection(host,port,ssl=ctx,server_hostname=host if tls else None),timeout=timeout)
        return {"ok":True,"latency_ms":round((time.perf_counter()-started)*1000,1)}
    except Exception as exc:
        return {"ok":False,"latency_ms":round((time.perf_counter()-started)*1000,1),"error":str(exc)[:120]}
    finally:
        if writer:
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass

async def _probe_proxy(row, timeout=4.0):
    """Check that the configured proxy listener is reachable.

    This deliberately checks the proxy endpoint itself, not an arbitrary
    destination. It works for HTTP and SOCKS listeners and avoids leaking
    stored credentials while still catching dead hosts and closed ports.
    """
    return await _probe(
        str(row.get("host") or ""),
        int(row.get("port") or 0),
        timeout,
        str(row.get("scheme") or "").lower() == "https",
    )

def build_router(require_perm):
    r=APIRouter(prefix="/api/pools",tags=["pools"]); dep=Depends(require_perm("settings"))
    @r.get("")
    async def get_pools(_=dep):
        d=_load(); return {"ok":True,"ips":[_public_ip(x) for x in d["ips"]],"proxies":[_public_proxy(x) for x in d["proxies"]]}
    @r.post("/ips")
    async def add_ips(request:Request,_=dep):
        b=await request.json(); raw=b.get("ips") or b.get("value") or []
        if isinstance(raw,str): raw=re.split(r"[\s,]+",raw)
        d=_load(); out=[]
        for item in raw[:200]:
            try:
                host, port = _split_host_port(item)
            except (TypeError, ValueError, HTTPException):
                continue
            host=_clean_host(host); key=f"{host}:{port}"
            if not any(f"{x['host']}:{x['port']}"==key for x in d["ips"]):
                row={"id":_id("ip"),"host":host,"port":port,"sni":str(b.get("sni") or "").strip().lower(),"enabled":True,"status":"untested","latency_ms":None,"last_check":""}
                d["ips"].append(row); out.append(row)
        _save(d); return {"ok":True,"added":len(out),"ips":[_public_ip(x) for x in d["ips"]]}
    @r.delete("/ips/{entry_id}")
    async def delete_ip(entry_id:str,_=dep):
        d=_load(); before=len(d["ips"]); d["ips"]=[x for x in d["ips"] if x.get("id")!=entry_id]
        if len(d["ips"])==before: raise HTTPException(404,"IP پیدا نشد")
        _save(d); return {"ok":True}
    @r.post("/ips/check")
    async def check_ips(request:Request,_=dep):
        b=await request.json(); ids=set(str(x) for x in (b.get("ids") or [])); d=_load(); rows=[x for x in d["ips"] if not ids or x.get("id") in ids]
        async def one(x):
            res=await _probe(x["host"],int(x["port"]),3.0,bool(x.get("port") in {443,2053,2083,2087,2096,8443}))
            x.update(status="healthy" if res["ok"] else "down",latency_ms=res.get("latency_ms"),last_check=datetime.now().isoformat(),error=res.get("error","")); return x
        await asyncio.gather(*(one(x) for x in rows)); _save(d)
        good=sorted([x for x in rows if x.get("status")=="healthy"],key=lambda x:x.get("latency_ms") or 999999)
        return {"ok":True,"checked":len(rows),"healthy":len(good),"ips":[_public_ip(x) for x in good]}
    @r.post("/proxies")
    async def add_proxy(request:Request,_=dep):
        b=await request.json(); raw=str(b.get("url") or b.get("proxy") or "").strip()
        if not raw: raise HTTPException(400,"آدرس Proxy لازم است")
        try:
            u=urlsplit(raw if "://" in raw else "http://"+raw)
            scheme=u.scheme.lower()
            host=(u.hostname or "").strip().lower()
            port=int(u.port or 0)
        except (ValueError, TypeError):
            raise HTTPException(400,"آدرس Proxy یا پورت نامعتبر است")
        if scheme not in _PROXY_SCHEMES or not host or not 1 <= port <= 65535:
            raise HTTPException(400,"Proxy باید HTTP یا SOCKS4/SOCKS5 و دارای پورت معتبر باشد")
        d=_load()
        if any(x.get("scheme")==scheme and x.get("host")==host and int(x.get("port") or 0)==port for x in d["proxies"]):
            raise HTTPException(409,"این Proxy قبلاً در مخزن ثبت شده است")
        row={"id":_id("px"),"scheme":scheme,"host":host,"port":port,"username":u.username or "","password":u.password or "","country":str(b.get("country") or "").upper()[:2],"enabled":True,"status":"untested","latency_ms":None,"last_check":""}
        d["proxies"].append(row); _save(d); return {"ok":True,"proxy":_public_proxy(row)}
    @r.post("/proxies/check")
    async def check_proxies(request:Request,_=dep):
        """Check every saved proxy listener, or only the requested ids."""
        try:
            b=await request.json()
        except Exception:
            b={}
        ids=set(str(x) for x in (b.get("ids") or []))
        d=_load()
        rows=[x for x in d["proxies"] if not ids or str(x.get("id")) in ids]

        async def one(x):
            res=await _probe_proxy(x, 4.0)
            x.update(
                status="healthy" if res["ok"] else "down",
                latency_ms=res.get("latency_ms"),
                last_check=datetime.now().isoformat(),
                error=res.get("error",""),
            )
            return x

        await asyncio.gather(*(one(x) for x in rows))
        good=sorted(
            [x for x in rows if x.get("status")=="healthy"],
            key=lambda x:x.get("latency_ms") or 999999,
        )
        _save(d)
        return {
            "ok":True,
            "checked":len(rows),
            "healthy":len(good),
            "proxies":[_public_proxy(x) for x in good],
        }
    @r.delete("/proxies/{entry_id}")
    async def delete_proxy(entry_id:str,_=dep):
        d=_load(); before=len(d["proxies"]); d["proxies"]=[x for x in d["proxies"] if x.get("id")!=entry_id]
        if len(d["proxies"])==before: raise HTTPException(404,"Proxy پیدا نشد")
        _save(d); return {"ok":True}
    return r
