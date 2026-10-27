"""ONEX bridge: serve /onex/vmess and /onex/xhttp from inside the
panel (uvicorn) instead of pinning raw TCP connections in the front proxy.

Why: Railway's edge re-uses upstream keep-alive connections across requests.
The front proxy chose a backend only from the FIRST request of a connection,
so a connection once handed to Xray later carried /httpup/... (and Railway)
requests into Xray, and vice-versa. uvicorn parses every request itself, so
routing here is per-request (like a Node http server + http-proxy per request).

  * WebSocket /onex/vmess   -> ws://127.0.0.1:18501/onex/vmess (Xray VMess-WS)
  * GET/POST  /onex/xhttp*  -> http://127.0.0.1:18503/onex/xhttp* (Xray VLESS-XHTTP)

Legacy paths from older builds are still served (rewritten to the /onex/*
paths before reaching Xray) so old client configs keep working.
"""
from __future__ import annotations

import asyncio
import logging
import os

import httpx
import websockets
from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from starlette.background import BackgroundTask
from starlette.responses import Response, StreamingResponse

logger = logging.getLogger("ONEX.Bridge")

VMESS_PORT = int(os.environ.get("ONEX_SR_VMESS_PORT", "18501"))
XHTTP_PORT = int(os.environ.get("ONEX_SR_XHTTP_PORT", "18503"))

NEW_VMESS_PATH = "/onex/vmess"
NEW_XHTTP_PATH = "/onex/xhttp"
# Legacy paths from older builds: kept ONLY so already-issued client configs keep working.
LEGACY_VMESS_PATH = "/siderail/vmess"
LEGACY_XHTTP_PATH = "/siderail/xhttp"

router = APIRouter()

HOP = {
    "connection", "keep-alive", "proxy-connection", "transfer-encoding", "te",
    "trailer", "upgrade", "content-length", "host",
}

_client: httpx.AsyncClient | None = None


def _http() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            http1=True, http2=False, timeout=httpx.Timeout(None, connect=10.0),
            limits=httpx.Limits(max_connections=2000, max_keepalive_connections=200),
        )
    return _client


# ---------------- VMess + WebSocket ----------------
async def onex_vmess(ws: WebSocket):
    await ws.accept()
    target = f"ws://127.0.0.1:{VMESS_PORT}{NEW_VMESS_PATH}"
    try:
        upstream = await websockets.connect(
            target, max_size=None, compression=None, ping_interval=None,
            open_timeout=10, close_timeout=2,
        )
    except Exception as exc:
        logger.warning("ONEX vmess: Xray not reachable: %s", exc)
        await ws.close(code=1011)
        return

    async def c2u():
        try:
            while True:
                msg = await ws.receive()
                if msg.get("type") == "websocket.disconnect":
                    break
                data = msg.get("bytes")
                if data is None and msg.get("text") is not None:
                    data = msg["text"].encode()
                if data:
                    await upstream.send(data)
        except (WebSocketDisconnect, websockets.ConnectionClosed, RuntimeError):
            pass

    async def u2c():
        try:
            async for data in upstream:
                if isinstance(data, str):
                    data = data.encode()
                await ws.send_bytes(data)
        except (WebSocketDisconnect, websockets.ConnectionClosed, RuntimeError):
            pass

    t1, t2 = asyncio.create_task(c2u()), asyncio.create_task(u2c())
    try:
        await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in (t1, t2):
            t.cancel()
        try:
            await upstream.close()
        except Exception:
            pass
        try:
            await ws.close()
        except Exception:
            pass


# ---------------- VLESS + XHTTP ----------------
async def _xhttp_proxy(request: Request):
    path = request.url.path
    if path == LEGACY_XHTTP_PATH or path.startswith(LEGACY_XHTTP_PATH + "/"):
        path = NEW_XHTTP_PATH + path[len(LEGACY_XHTTP_PATH):]
    url = f"http://127.0.0.1:{XHTTP_PORT}{path}"
    if request.url.query:
        url += "?" + request.url.query
    headers = [(k, v) for k, v in request.headers.items() if k.lower() not in HOP]
    host = request.headers.get("host")
    if host:
        headers.append(("host", host))
    body = request.stream() if request.method not in ("GET", "HEAD") else None
    client = _http()
    try:
        req = client.build_request(request.method, url, headers=headers, content=body)
        resp = await client.send(req, stream=True)
    except Exception as exc:
        logger.warning("ONEX xhttp: Xray not reachable: %s", exc)
        return Response(status_code=502)
    out_headers = {k: v for k, v in resp.headers.items() if k.lower() not in HOP}
    out_headers.setdefault("x-accel-buffering", "no")
    out_headers.setdefault("cache-control", "no-store")
    return StreamingResponse(
        resp.aiter_raw(), status_code=resp.status_code, headers=out_headers,
        background=BackgroundTask(resp.aclose),
    )


router.add_api_websocket_route(NEW_VMESS_PATH, onex_vmess)
router.add_api_websocket_route(LEGACY_VMESS_PATH, onex_vmess)

for _base in (NEW_XHTTP_PATH, LEGACY_XHTTP_PATH):
    router.add_api_route(_base, _xhttp_proxy, methods=["GET", "POST", "HEAD"], include_in_schema=False)
    router.add_api_route(_base + "/{tail:path}", _xhttp_proxy, methods=["GET", "POST", "HEAD"], include_in_schema=False)
