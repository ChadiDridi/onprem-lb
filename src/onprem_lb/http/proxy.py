"""Application load balancer listener (HTTP/1.1 and HTTPS)."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
import uuid
from typing import TYPE_CHECKING

from .. import config, stream
from ..algorithms import PickContext
from ..tlsutil import SNIContexts
from . import parser as hp
from . import rules

if TYPE_CHECKING:
    from ..runtime import Runtime
    from ..targets import Target, TargetGroup

log = logging.getLogger("onprem_lb.http")
access = logging.getLogger("onprem_lb.access")

HOP_BY_HOP = ("connection", "keep-alive", "proxy-connection", "te", "trailer", "upgrade")
REASONS = {
    200: "OK",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    400: "Bad Request",
    404: "Not Found",
    408: "Request Timeout",
    413: "Payload Too Large",
    431: "Request Header Fields Too Large",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    505: "HTTP Version Not Supported",
}
CONNECT_ATTEMPTS = 3


class Pool:
    """Idle keep-alive connections to targets."""

    MAX_IDLE_PER_TARGET = 64
    IDLE_SECONDS = 50.0  # below common upstream keep-alive timeouts (60s+)

    def __init__(self) -> None:
        self.idle: dict[str, list[tuple[asyncio.StreamReader, asyncio.StreamWriter, float]]] = {}

    async def get(self, t: Target, tg: TargetGroup, timeout: float):
        now = time.monotonic()
        conns = self.idle.get(t.address)
        while conns:
            r, w, since = conns.pop()
            if now - since < self.IDLE_SECONDS and not r.at_eof() and not w.is_closing():
                return r, w, True
            stream.close(w)
        r, w = await asyncio.wait_for(asyncio.open_connection(t.host, t.port, ssl=tg.upstream_ssl), timeout)
        return r, w, False

    def put(self, t: Target, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        conns = self.idle.setdefault(t.address, [])
        if len(conns) >= self.MAX_IDLE_PER_TARGET or t.state == "draining":
            stream.close(w)
            return
        conns.append((r, w, time.monotonic()))

    def close_all(self) -> None:
        for conns in self.idle.values():
            for _, w, _ in conns:
                stream.close(w)
        self.idle.clear()


class _UpstreamFailed(Exception):
    def __init__(self, status: int, kind: str) -> None:
        self.status, self.kind = status, kind


class _AbortClient(Exception):
    """Failure after the response head went out: all we can do is close."""


class HTTPListener:
    def __init__(self, lb: str, spec: config.Listener, rt: Runtime) -> None:
        self.lb, self.spec, self.rt = lb, spec, rt
        self.name = f"{spec.protocol}:{spec.port}"
        self.scheme = spec.protocol
        self.sni = SNIContexts(spec.certificates, alpn=["http/1.1"]) if spec.protocol == "https" else None
        self.server: asyncio.base_events.Server | None = None
        self.clients: set[asyncio.Task] = set()

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self._handle,
            self.spec.bind,
            self.spec.port,
            ssl=self.sni.front if self.sni else None,
            ssl_handshake_timeout=10 if self.sni else None,
            reuse_address=True,
            reuse_port=self.rt.reuse_port or None,
            limit=hp.MAX_HEAD,
        )

    def update(self, spec: config.Listener) -> None:
        if self.sni:
            self.sni.load(spec.certificates)
        self.spec = spec

    async def stop(self, grace: float = 0.0) -> None:
        if self.server:
            self.server.close()
        if grace > 0 and self.clients:
            await asyncio.wait(list(self.clients), timeout=grace)
        for t in list(self.clients):
            t.cancel()
        if self.clients:
            await asyncio.gather(*self.clients, return_exceptions=True)

    # ------------------------------------------------------------------ client loop

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        self.clients.add(task)
        m = self.rt.metrics
        labels = (self.lb, self.name)
        if len(self.clients) > self.spec.max_connections:
            m.rejected.inc(*labels)
            await self._simple(writer, 503, "too many connections", close=True)
            stream.close(writer)
            self.clients.discard(task)
            return
        m.connections.inc(*labels)
        m.active.set(*labels, value=len(self.clients))
        peer = writer.get_extra_info("peername") or ("", 0)
        try:
            client_ip = ipaddress.ip_address(peer[0].split("%")[0]) if peer[0] else None
        except ValueError:
            client_ip = None
        first = True
        try:
            while True:
                timeout = self.spec.timeouts.client_header if first else self.spec.timeouts.idle
                first = False
                try:
                    head = await asyncio.wait_for(hp.read_head(reader), timeout)
                except TimeoutError:
                    return
                except hp.HTTPError as e:
                    await self._simple(writer, e.status, str(e), close=True)
                    return
                if head is None:
                    return
                try:
                    req = hp.parse_request(head)
                    framing = hp.request_framing(req.headers)
                except hp.HTTPError as e:
                    await self._simple(writer, e.status, str(e), close=True)
                    return
                keep = await self._request(req, framing, reader, writer, peer, client_ip)
                if not keep:
                    return
        except (TimeoutError, OSError, asyncio.IncompleteReadError):
            pass
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - never let one client kill the listener
            log.exception("unhandled error serving %s", peer)
        finally:
            stream.close(writer)
            self.clients.discard(task)
            m.active.set(*labels, value=len(self.clients))

    def _client_keepalive(self, req: hp.Request) -> bool:
        conn = req.headers.tokens("connection")
        if req.version == "HTTP/1.1":
            return "close" not in conn
        return "keep-alive" in conn

    async def _simple(self, writer, status: int, body: str, close: bool, headers=(), content_type="text/plain") -> None:
        data = body.encode()
        h = hp.Headers([("Content-Type", content_type), ("Content-Length", str(len(data))), *headers])
        if close:
            h.set("Connection", "close")
        writer.write(f"HTTP/1.1 {status} {REASONS.get(status, '')}\r\n".encode() + h.encode() + b"\r\n" + data)
        try:
            await writer.drain()
        except OSError:
            pass

    # ------------------------------------------------------------------ one request

    async def _request(self, req, framing, reader, writer, peer, client_ip) -> bool:
        """Serve one request. Returns whether the client connection stays open."""
        start = time.monotonic()
        keep = self._client_keepalive(req)
        view = rules.RequestView(req, rules.host_of(req), client_ip, self.scheme, self.spec.port)
        action = rules.select(self.spec, view)
        body_kind, body_len = framing

        if action.type != "forward":
            if body_kind != hp.NONE:
                keep = False  # don't bother reading a body we won't forward
            if action.type == "redirect":
                loc = rules.redirect_location(action.location, view)
                await self._simple(writer, action.status, "", close=not keep, headers=[("Location", loc)])
            else:
                await self._simple(writer, action.status, action.body, close=not keep, headers=list(action.headers), content_type=action.content_type)
            self._log(req, peer, action.status, "-", "-", start)
            return keep

        tg_name = rules.pick_group(action)
        tg = self.rt.groups[tg_name]
        if req.headers.tokens("expect") == {"100-continue"}:
            # Answer 100 ourselves so the client sends the body while we
            # pick and connect; the upstream never sees Expect.
            req.headers.remove("expect")
            writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")

        try:
            return await self._forward(req, body_kind, body_len, reader, writer, peer, view, tg, keep, start)
        except _AbortClient:
            return False
        except hp.HTTPError as e:  # malformed request body framing
            self._log(req, peer, e.status, tg_name, "-", start)
            await self._simple(writer, e.status, str(e) + "\n", close=True)
            return False
        except _UpstreamFailed as e:
            self.rt.metrics.upstream_errors.inc(tg_name, e.kind)
            self.rt.metrics.requests.inc(self.lb, self.name, tg_name, f"{e.status // 100}xx")
            self._log(req, peer, e.status, tg_name, "-", start)
            msg = {502: "bad gateway", 503: "no healthy targets", 504: "upstream timeout"}.get(e.status, "error")
            # The request body may be half-read; the connection can't be reused.
            await self._simple(writer, e.status, msg + "\n", close=True)
            return False

    async def _forward(self, req, body_kind, body_len, reader, writer, peer, view, tg: TargetGroup, keep, start) -> bool:
        m = self.rt.metrics
        spec = tg.spec
        upgrade = "upgrade" in req.headers.tokens("connection") and req.headers.get("upgrade")

        # Sticky target first, then the balancer.
        sticky_target = None
        set_cookie = None
        if spec.stickiness.enabled:
            sid = rules.cookie(req, spec.stickiness.cookie)
            sticky_target = tg.by_sticky_id(sid) if sid else None
        ctx = PickContext(
            client_ip=str(view.client_ip or ""),
            client_port=peer[1] if len(peer) > 1 else 0,
            key=rules.hash_key(spec, view, peer[1] if len(peer) > 1 else 0),
        )

        # Request head for the upstream.
        h = req.headers.copy()
        drop = set(HOP_BY_HOP) | req.headers.tokens("connection")
        h.remove(*drop)
        if upgrade:
            h.set("Connection", "Upgrade")
            h.set("Upgrade", upgrade)
        xff = req.headers.get("x-forwarded-for")
        ip = str(view.client_ip or "")
        h.set("X-Forwarded-For", f"{xff}, {ip}" if xff else ip)
        h.set("X-Forwarded-Proto", self.scheme)
        h.set("X-Forwarded-Port", str(self.spec.port))
        if not h.get("x-request-id"):
            h.set("X-Request-Id", uuid.uuid4().hex)
        if req.headers.get("host") is None:
            h.set("Host", view.host or "")
        head = f"{req.method} {req.target} HTTP/1.1\r\n".encode("latin-1") + h.encode() + b"\r\n"

        # Connect (retry other targets on connect failure; nothing sent yet).
        tried: set[str] = set()
        target = up_r = up_w = None
        reused = False
        for _ in range(CONNECT_ATTEMPTS):
            t = sticky_target if sticky_target and not tried else tg.pick(ctx, frozenset(tried))
            if t is None:
                break
            try:
                up_r, up_w, reused = await self.rt.pool.get(t, tg, self.spec.timeouts.connect)
                t.connect_ok()
                target = t
                break
            except (TimeoutError, OSError):
                t.connect_failed()
                tried.add(t.address)
                m.upstream_errors.inc(spec.name, "connect")
        if target is None:
            raise _UpstreamFailed(503 if not tried else 502, "no_target" if not tried else "connect")
        if spec.stickiness.enabled and target is not sticky_target:
            s = spec.stickiness
            set_cookie = f"{s.cookie}={target.sticky_id}; Max-Age={s.duration}; Path=/; HttpOnly; SameSite=Lax"

        tg.begin(target)
        closer = lambda: stream.close(writer, up_w, abort=True)  # noqa: E731
        target.closers.add(closer)
        upstream_reusable = False
        head_sent = False
        try:
            resp = await self._exchange(req, head, body_kind, body_len, reader, up_r, up_w, reused, tg, target)
            if resp is None:  # stale pooled connection, request had no body: retry once fresh
                stream.close(up_w)
                up_r, up_w = await asyncio.wait_for(
                    asyncio.open_connection(target.host, target.port, ssl=tg.upstream_ssl), self.spec.timeouts.connect
                )
                resp = await self._exchange(req, head, body_kind, body_len, reader, up_r, up_w, False, tg, target)
                if resp is None:
                    raise _UpstreamFailed(502, "reset")
            elapsed = time.monotonic() - start
            target.observe(elapsed)
            m.duration.observe(elapsed, self.lb, self.name, spec.name)
            m.requests.inc(self.lb, self.name, spec.name, f"{resp.status // 100}xx")

            # Response head for the client.
            rh = resp.headers.copy()
            rh.remove(*(set(HOP_BY_HOP) | resp.headers.tokens("connection")))
            if set_cookie:
                rh.add("Set-Cookie", set_cookie)

            if resp.status == 101 and upgrade:
                rh.set("Connection", "Upgrade")
                rh.set("Upgrade", resp.headers.get("upgrade") or upgrade)
                writer.write(f"HTTP/1.1 101 {resp.reason}\r\n".encode("latin-1") + rh.encode() + b"\r\n")
                head_sent = True
                await writer.drain()
                self._log(req, peer, 101, spec.name, target.address, start)
                await stream.splice(reader, writer, up_r, up_w, self.spec.timeouts.idle)
                return False

            kind, n = hp.response_framing(req.method, resp.status, resp.headers)
            rechunk = False
            if kind == hp.CLOSE:
                if req.version == "HTTP/1.1":
                    rh.remove("transfer-encoding", "content-length")
                    rh.set("Transfer-Encoding", "chunked")
                    rechunk = True
                else:
                    keep = False
            if keep:
                if req.version == "HTTP/1.0":
                    rh.set("Connection", "keep-alive")
            else:
                rh.set("Connection", "close")
            writer.write(f"HTTP/1.1 {resp.status} {resp.reason}\r\n".encode("latin-1") + rh.encode() + b"\r\n")
            head_sent = True
            sent = await hp.copy_body(kind, n, up_r, writer, self.spec.timeouts.idle, rechunk)
            await writer.drain()
            m.bytes.inc(self.lb, self.name, "out", by=sent)
            upstream_reusable = kind != hp.CLOSE and resp.version == "HTTP/1.1" and "close" not in resp.headers.tokens("connection")
            self._log(req, peer, resp.status, spec.name, target.address, start)
            return keep
        except TimeoutError:
            if head_sent:
                raise _AbortClient() from None
            raise _UpstreamFailed(504, "timeout") from None
        except hp.HTTPError as e:
            if head_sent:
                raise _AbortClient() from None
            if e.status == 502:
                raise _UpstreamFailed(502, "protocol") from None
            raise
        except (OSError, asyncio.IncompleteReadError):
            if head_sent:
                raise _AbortClient() from None
            raise _UpstreamFailed(502, "reset") from None
        finally:
            target.closers.discard(closer)
            tg.end(target)
            if upstream_reusable:
                self.rt.pool.put(target, up_r, up_w)
            else:
                stream.close(up_w)

    async def _exchange(self, req, head, body_kind, body_len, reader, up_r, up_w, reused, tg, target):
        """Send the request and read the final response head. Returns None if a
        reused connection turned out stale before anything was read and the
        request is safely retryable (no body)."""
        try:
            up_w.write(head)
            await up_w.drain()
            if body_kind != hp.NONE:
                await hp.copy_body(body_kind, body_len, reader, up_w, self.spec.timeouts.idle)
                await up_w.drain()
            while True:
                raw = await asyncio.wait_for(hp.read_head(up_r), self.spec.timeouts.response)
                if raw is None:
                    raise asyncio.IncompleteReadError(b"", None)
                resp = hp.parse_response(raw)
                if resp.status == 100 or (100 < resp.status < 200 and resp.status != 101):
                    continue  # interim responses: we already answered 100 ourselves
                return resp
        except (OSError, asyncio.IncompleteReadError):
            if reused and body_kind == hp.NONE:
                return None
            raise

    def _log(self, req, peer, status, tg, target, start) -> None:
        if access.isEnabledFor(logging.INFO):
            access.info(
                '%s "%s %s %s" %d %s %s %.1fms',
                peer[0] if peer else "-",
                req.method,
                req.target,
                req.version,
                status,
                tg,
                target,
                (time.monotonic() - start) * 1000,
            )
