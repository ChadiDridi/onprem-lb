"""Admin REST API: create, change and delete load balancers on demand.

All routes except /healthz and /metrics need ``Authorization: Bearer <token>``
when a token is configured. The server refuses to listen on a non-loopback
address without a token.
"""

from __future__ import annotations

import asyncio
import copy
import hmac
import ipaddress
import json
import logging
from typing import Any
from urllib.parse import unquote

import yaml

from . import __version__, config, stream
from .http import parser as hp
from .runtime import Runtime

log = logging.getLogger("onprem_lb.admin")

MAX_BODY = 1 << 20


class APIError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class AdminServer:
    def __init__(self, rt: Runtime, token: str | None) -> None:
        self.rt = rt
        self.token = token or None
        self.server: asyncio.base_events.Server | None = None

    async def start(self, host: str, port: int) -> None:
        if not self.token and not _loopback(host):
            raise RuntimeError(f"admin API on non-loopback {host} needs a token: set the env var named by admin.token_env")
        self.server = await asyncio.start_server(self._handle, host, port, limit=hp.MAX_HEAD)

    async def stop(self) -> None:
        if self.server:
            self.server.close()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                raw = await asyncio.wait_for(hp.read_head(reader), 30)
                if raw is None:
                    return
                req = hp.parse_request(raw)
                kind, n = hp.request_framing(req.headers)
                if kind == hp.CHUNKED or n > MAX_BODY:
                    await self._send(writer, 413, {"error": "body must be Content-Length and <= 1 MiB"}, close=True)
                    return
                body = await reader.readexactly(n) if n else b""
                try:
                    status, payload = await self._route(req, body)
                except APIError as e:
                    status, payload = e.status, {"error": str(e)}
                except config.ConfigError as e:
                    status, payload = 400, {"error": str(e)}
                except OSError as e:
                    status, payload = 409, {"error": f"could not apply: {e}"}
                keep = "close" not in req.headers.tokens("connection")
                await self._send(writer, status, payload, close=not keep)
                if not keep:
                    return
        except hp.HTTPError as e:
            await self._send(writer, e.status, {"error": str(e)}, close=True)
        except (TimeoutError, OSError, asyncio.IncompleteReadError):
            pass
        finally:
            stream.close(writer)

    async def _send(self, writer, status: int, payload: Any, close: bool) -> None:
        if isinstance(payload, str):
            data, ctype = payload.encode(), "text/plain; version=0.0.4"
        else:
            data, ctype = (json.dumps(payload, indent=2, default=str) + "\n").encode(), "application/json"
        head = f"HTTP/1.1 {status} {'OK' if status < 400 else 'Error'}\r\nContent-Type: {ctype}\r\nContent-Length: {len(data)}\r\n"
        if close:
            head += "Connection: close\r\n"
        writer.write(head.encode() + b"\r\n" + data)
        await writer.drain()

    # ------------------------------------------------------------------ routing

    def _authorized(self, req: hp.Request) -> bool:
        if not self.token:
            return True
        got = req.headers.get("authorization") or ""
        return hmac.compare_digest(got.encode(), f"Bearer {self.token}".encode())

    async def _route(self, req: hp.Request, body: bytes) -> tuple[int, Any]:
        parts = [unquote(p) for p in req.path.strip("/").split("/") if p]
        m = req.method
        if parts == ["healthz"] and m == "GET":
            return 200, {"status": "ok", "version": __version__}
        if parts == ["metrics"] and m == "GET":
            return 200, await self.rt.metrics_text()
        if not self._authorized(req):
            raise APIError(401, "missing or wrong bearer token")

        if parts == ["config"]:
            if m == "GET":
                return 200, self.rt.raw
            if m == "PUT":
                await self.rt.apply(_decode(req, body))
                return 200, self.rt.raw
        if parts == ["state"] and m == "GET":
            return 200, await self.rt.state()

        if parts and parts[0] in ("load-balancers", "target-groups"):
            section = "load_balancers" if parts[0] == "load-balancers" else "target_groups"
            if len(parts) == 1 and m == "GET":
                return 200, self.rt.raw.get(section) or {}
            if len(parts) == 2:
                return await self._resource(section, parts[1], m, req, body)
            if section == "target_groups" and len(parts) >= 3 and parts[2] == "targets":
                return await self._targets(parts[1], parts[3] if len(parts) == 4 else None, m, req, body)
        raise APIError(404, f"no route for {m} {req.path}")

    async def _change(self, mutate) -> None:
        raw = copy.deepcopy(self.rt.raw)
        mutate(raw)
        await self.rt.apply(raw)

    async def _resource(self, section: str, name: str, m: str, req, body) -> tuple[int, Any]:
        items = self.rt.raw.get(section) or {}
        if m == "GET":
            if name not in items:
                raise APIError(404, f"{section[:-1].replace('_', ' ')} {name!r} not found")
            out = {"name": name, "spec": items[name]}
            if section == "target_groups":
                out["status"] = await self.rt.group_state(name)
            return 200, out
        if m == "PUT":
            spec = _decode(req, body)
            created = name not in items
            await self._change(lambda raw: raw.setdefault(section, {}).__setitem__(name, spec))
            return (201 if created else 200), {"name": name, "spec": spec}
        if m == "DELETE":
            if name not in items:
                raise APIError(404, f"{name!r} not found")
            await self._change(lambda raw: raw[section].pop(name))
            return 200, {"deleted": name}
        raise APIError(405, "method not allowed")

    async def _targets(self, group: str, address: str | None, m: str, req, body) -> tuple[int, Any]:
        groups = self.rt.raw.get("target_groups") or {}
        if group not in groups:
            raise APIError(404, f"target group {group!r} not found")

        def find(raw: dict, addr: str) -> int:
            for i, t in enumerate(raw["target_groups"][group].get("targets") or []):
                if (t if isinstance(t, str) else t.get("address")) == addr:
                    return i
            return -1

        if address is None and m == "GET":
            return 200, await self.rt.group_state(group)
        if address is None and m == "POST":
            t = _decode(req, body)
            if not isinstance(t, dict) or "address" not in t:
                raise APIError(400, 'body must be {"address": "host:port", "weight": 1}')
            if find(self.rt.raw, t["address"]) >= 0:
                raise APIError(409, f"target {t['address']} already registered")
            await self._change(lambda raw: raw["target_groups"][group].setdefault("targets", []).append(t))
            return 201, t
        if address is not None and m == "PUT":
            patch = _decode(req, body)
            if not isinstance(patch, dict):
                raise APIError(400, "body must be an object")

            def upd(raw: dict) -> None:
                i = find(raw, address)
                if i < 0:
                    raise APIError(404, f"target {address} not registered")
                ts = raw["target_groups"][group]["targets"]
                cur = ts[i] if isinstance(ts[i], dict) else {"address": ts[i]}
                ts[i] = {**cur, **patch, "address": address}

            await self._change(upd)
            return 200, {"address": address, **patch}
        if address is not None and m == "DELETE":

            def rm(raw: dict) -> None:
                i = find(raw, address)
                if i < 0:
                    raise APIError(404, f"target {address} not registered")
                raw["target_groups"][group]["targets"].pop(i)

            await self._change(rm)
            return 200, {"deregistered": address, "draining_seconds": self.rt.config.target_groups[group].deregistration_delay}
        raise APIError(405, "method not allowed")


def _decode(req: hp.Request, body: bytes) -> Any:
    ctype = (req.headers.get("content-type") or "").lower()
    try:
        if "yaml" in ctype:
            return yaml.safe_load(body)
        return json.loads(body or b"null")
    except (ValueError, yaml.YAMLError) as e:
        raise APIError(400, f"invalid body: {e}") from None


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
