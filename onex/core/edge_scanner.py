"""Bounded Cloudflare/Railway endpoint scanner for ONEX.

It probes only explicitly supplied or bundled provider ranges. It is not an
open-ended port scanner. Cloudflare ranges are expanded lazily and capped.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import random
import socket
import ssl
import time
from pathlib import Path

DEFAULT_CLOUDFLARE_CIDRS = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
)


def _parse_endpoint(value: str, default_port: int = 443) -> tuple[str, int] | None:
    value = str(value or "").strip()
    if not value or value.startswith("#"):
        return None
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        try:
            return host.strip(), max(1, min(65535, int(port)))
        except ValueError:
            return None
    return value.strip("[]"), default_port


def _expand_network(raw: str, limit: int, mode: str) -> list[tuple[str, int]]:
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return []
    # Never materialise a giant network. Full mode is still bounded by the
    # request limit and sampling remains deterministic for repeatable results.
    total = max(0, net.num_addresses - (2 if net.version == 4 and net.num_addresses > 2 else 0))
    take = min(max(1, limit), total)
    if take <= 0:
        return []
    if mode == "sample" and total > take:
        rng = random.Random(str(net))
        offsets = sorted(rng.sample(range(total), take))
    else:
        offsets = range(take)
    first = int(net.network_address) + (1 if net.version == 4 and net.num_addresses > 2 else 0)
    return [(str(ipaddress.ip_address(first + i)), 443) for i in offsets]


def load_candidates(root: Path, source: str, limit: int = 80, mode: str = "sample") -> list[tuple[str, int]]:
    """Load and expand provider candidates with validation and hard caps."""
    source = str(source or "cloudflare").lower()
    if source not in {"cloudflare", "onex-ready", "railway"}:
        source = "cloudflare"
    limit = max(1, min(4096, int(limit or 80)))
    values: list[str] = []
    prepared_loaded = False
    # ONEX ships a large, prepared candidate file. The ready-IP screen must
    # scan this file instead of silently falling back to provider CIDR ranges.
    if source == "onex-ready":
        prepared_files = (
            root / "onex_repo" / "ips.txt",
            root / "data" / "cloudflare_ips.txt",
            root / "config" / "cloudflare_ips.txt",
        )
        for path in prepared_files:
            if path.is_file():
                values.extend(path.read_text(errors="ignore").splitlines())
                prepared_loaded = True
                break
    if source == "railway":
        files = (root / "data" / "endpoint.txt", root / "config" / "endpoint.txt")
    else:
        files = (root / "data" / "cf_subnets.txt", root / "config" / "cf_subnets.txt")
    # Only use the older subnet files when the prepared file is absent.
    if not values:
        for path in files:
            if path.is_file():
                values.extend(path.read_text(errors="ignore").splitlines())
                break
    if source == "cloudflare" and not values:
        values = list(DEFAULT_CLOUDFLARE_CIDRS)

    # The shipped file also has a small number of hostnames. This screen is
    # explicitly an IP tester, so keep only literal IPv4/IPv6 entries from it.
    if source == "onex-ready" and prepared_loaded:
        ip_values: list[str] = []
        for raw in values:
            value = raw.strip()
            if not value or value.startswith("#"):
                continue
            parsed = _parse_endpoint(value)
            if not parsed:
                continue
            try:
                ipaddress.ip_address(parsed[0])
            except ValueError:
                continue
            ip_values.append(value)
        values = ip_values
    if source == "railway" and not values:
        target = (os.environ.get("RAILWAY_PUBLIC_DOMAIN") or os.environ.get("RAILWAY_STATIC_URL") or os.environ.get("ONEX_PUBLIC_URL") or "")
        target = target.split("://", 1)[-1].split("/", 1)[0].rsplit(":", 1)[0]
        if target:
            try:
                values = [f"{item[4][0]}:443" for item in socket.getaddrinfo(target, 443, type=socket.SOCK_STREAM)]
            except OSError:
                values = []

    out: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    # The prepared file contains many hosts. Sampling from the whole file
    # prevents small scans from repeatedly testing only its first lines.
    if source == "onex-ready" and mode == "sample" and len(values) > limit:
        rng = random.Random(f"{root}:{len(values)}:{limit}")
        values = rng.sample(values, limit)
    per_range = max(1, min(limit, 512))
    for raw in values:
        raw = raw.strip()
        items = _expand_network(raw, per_range, mode) if "/" in raw else []
        if not items:
            item = _parse_endpoint(raw)
            items = [item] if item else []
        for item in items:
            if item and item not in seen:
                host, port = item
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    if not host or len(host) > 253:
                        continue
                seen.add(item)
                out.append(item)
                if len(out) >= limit:
                    return out
    return out


async def check_endpoint(host: str, port: int = 443, sni: str = "", timeout: float = 3.0, retries: int = 1) -> dict:
    started = time.perf_counter()
    last_error = ""
    for attempt in range(max(0, min(2, retries)) + 1):
        writer = None
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni or host), timeout=timeout
            )
            return {"host": host, "port": port, "ok": True,
                    "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                    "protocol": "tls", "sni": sni or host, "attempt": attempt + 1}
        except Exception as exc:
            last_error = str(exc)[:160]
            if attempt < retries:
                await asyncio.sleep(0.08 * (attempt + 1))
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
    return {"host": host, "port": port, "ok": False,
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            "error": last_error, "sni": sni or host, "attempt": retries + 1}


async def scan(candidates: list[tuple[str, int]], sni: str = "", timeout: float = 3.0, concurrency: int = 24, retries: int = 1) -> list[dict]:
    sem = asyncio.Semaphore(max(1, min(48, concurrency)))
    unique = list(dict.fromkeys(candidates))[:4096]

    async def one(host: str, port: int) -> dict:
        async with sem:
            return await check_endpoint(host, port, sni=sni, timeout=timeout, retries=retries)

    results = await asyncio.gather(*(one(h, p) for h, p in unique))
    return sorted(results, key=lambda item: (not item["ok"], item["latency_ms"]))
