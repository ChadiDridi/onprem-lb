"""Network load balancer listeners: TCP, TLS (terminated) and UDP."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING

from . import config, proxyproto, stream
from .algorithms import PickContext
from .tlsutil import SNIContexts

if TYPE_CHECKING:
    from .runtime import Runtime
    from .targets import Target, TargetGroup

log = logging.getLogger("onprem_lb.l4")

CONNECT_ATTEMPTS = 3


class TCPListener:
    def __init__(self, lb: str, spec: config.Listener, rt: Runtime) -> None:
        self.lb, self.spec, self.rt = lb, spec, rt
        self.name = f"{spec.protocol}:{spec.port}"
        self.server: asyncio.base_events.Server | None = None
        self.sni = SNIContexts(spec.certificates) if spec.protocol == "tls" else None
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
        )

    def update(self, spec: config.Listener) -> None:
        if self.sni:
            self.sni.load(spec.certificates)
        self.spec = spec

    async def stop(self, grace: float = 0.0) -> None:
        if self.server:
            self.server.close()
        await _drain_clients(self.clients, grace)

    def group(self) -> TargetGroup:
        return self.rt.groups[self.spec.default_action.forward[0].target_group]

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        self.clients.add(task)
        m = self.rt.metrics
        labels = (self.lb, self.name)
        if len(self.clients) > self.spec.max_connections:
            m.rejected.inc(*labels)
            stream.close(writer)
            self.clients.discard(task)
            return
        m.connections.inc(*labels)
        m.active.set(*labels, value=len(self.clients))
        up_w = None
        target = None
        tg = self.group()
        try:
            peer = writer.get_extra_info("peername") or ("", 0)
            local = writer.get_extra_info("sockname") or ("", 0)
            key = f"{peer[0]}:{peer[1]}" if tg.spec.hash_key == "source_ip_port" else peer[0]
            ctx = PickContext(client_ip=peer[0], client_port=peer[1], key=key)
            target, up_r, up_w = await connect(tg, ctx, self.spec.timeouts.connect, m)
            if target is None:
                return
            tg.begin(target)
            closer = lambda: stream.close(writer, up_w, abort=True)  # noqa: E731 - used for draining
            target.closers.add(closer)
            try:
                if tg.spec.proxy_protocol != "none":
                    up_w.write(proxyproto.header(tg.spec.proxy_protocol, peer[:2], local[:2]))
                await stream.splice(
                    reader,
                    writer,
                    up_r,
                    up_w,
                    self.spec.timeouts.idle,
                    lambda d, n: m.bytes.inc(self.lb, self.name, d, by=n),
                )
            finally:
                target.closers.discard(closer)
                tg.end(target)
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            stream.close(writer, up_w)
            self.clients.discard(task)
            m.active.set(*labels, value=len(self.clients))


async def connect(tg: TargetGroup, ctx: PickContext, timeout: float, m) -> tuple:
    """Pick and connect, retrying other targets on failure."""
    tried: set[str] = set()
    for _ in range(CONNECT_ATTEMPTS):
        t = tg.pick(ctx, frozenset(tried))
        if t is None:
            break
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(t.host, t.port, ssl=tg.upstream_ssl), timeout)
            t.connect_ok()
            return t, r, w
        except (TimeoutError, OSError) as e:
            t.connect_failed()
            tried.add(t.address)
            m.upstream_errors.inc(tg.spec.name, "connect")
            log.info("connect to %s failed: %s", t.address, e.__class__.__name__)
    m.upstream_errors.inc(tg.spec.name, "no_target")
    return None, None, None


async def _drain_clients(clients: set[asyncio.Task], grace: float) -> None:
    if grace > 0 and clients:
        await asyncio.wait(list(clients), timeout=grace)
    for t in list(clients):
        t.cancel()
    if clients:
        await asyncio.gather(*clients, return_exceptions=True)


# --------------------------------------------------------------------------- UDP


class _Session:
    __slots__ = ("client", "target", "group", "closer", "transport", "last", "pending", "ready")

    def __init__(self, client: tuple) -> None:
        self.client = client
        self.target: Target | None = None
        self.group: TargetGroup | None = None
        self.closer = None
        self.transport: asyncio.DatagramTransport | None = None
        self.last = time.monotonic()
        self.pending: list[bytes] = []
        self.ready = False


class _Front(asyncio.DatagramProtocol):
    def __init__(self, listener: UDPListener) -> None:
        self.l = listener

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self.l.on_datagram(data, addr)


class _Back(asyncio.DatagramProtocol):
    def __init__(self, listener: UDPListener, session: _Session) -> None:
        self.l, self.s = listener, session

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self.s.last = time.monotonic()
        if self.l.front:
            self.l.front.sendto(data, self.s.client)
            self.l.rt.metrics.bytes.inc(self.l.lb, self.l.name, "out", by=len(data))


class UDPListener:
    """Per-client sessions: datagrams from one client address go to the same
    target until the session idles out."""

    MAX_PENDING = 64

    def __init__(self, lb: str, spec: config.Listener, rt: Runtime) -> None:
        self.lb, self.spec, self.rt = lb, spec, rt
        self.name = f"udp:{spec.port}"
        self.front: asyncio.DatagramTransport | None = None
        self.sessions: dict[tuple, _Session] = {}
        self._sweeper: asyncio.Task | None = None
        self._tasks: set[asyncio.Task] = set()

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self.front, _ = await loop.create_datagram_endpoint(
            lambda: _Front(self), local_addr=(self.spec.bind, self.spec.port), reuse_port=self.rt.reuse_port or None
        )
        self._sweeper = asyncio.create_task(self._sweep())

    def update(self, spec: config.Listener) -> None:
        self.spec = spec

    async def stop(self, grace: float = 0.0) -> None:
        if self._sweeper:
            self._sweeper.cancel()
        if self.front:
            self.front.close()
        for s in list(self.sessions.values()):
            self._close(s)
        for t in list(self._tasks):
            t.cancel()

    def group(self) -> TargetGroup:
        return self.rt.groups[self.spec.default_action.forward[0].target_group]

    def on_datagram(self, data: bytes, addr: tuple) -> None:
        m = self.rt.metrics
        m.bytes.inc(self.lb, self.name, "in", by=len(data))
        s = self.sessions.get(addr)
        if s is None:
            if len(self.sessions) >= self.spec.max_connections:
                m.rejected.inc(self.lb, self.name)
                return
            s = self.sessions[addr] = _Session(addr)
            m.connections.inc(self.lb, self.name)
            m.udp_sessions.set(self.lb, self.name, value=len(self.sessions))
            t = asyncio.create_task(self._open(s))
            self._tasks.add(t)
            t.add_done_callback(self._tasks.discard)
        s.last = time.monotonic()
        if s.ready and s.transport:
            s.transport.sendto(data)
        elif len(s.pending) < self.MAX_PENDING:
            s.pending.append(data)

    async def _open(self, s: _Session) -> None:
        tg = self.group()
        key = f"{s.client[0]}:{s.client[1]}" if tg.spec.hash_key == "source_ip_port" else s.client[0]
        t = tg.pick(PickContext(client_ip=s.client[0], client_port=s.client[1], key=key))
        if t is None:
            self.rt.metrics.upstream_errors.inc(tg.spec.name, "no_target")
            self._close(s)
            return
        loop = asyncio.get_running_loop()
        try:
            s.transport, _ = await loop.create_datagram_endpoint(lambda: _Back(self, s), remote_addr=(t.host, t.port))
        except OSError:
            t.connect_failed()
            self.rt.metrics.upstream_errors.inc(tg.spec.name, "connect")
            self._close(s)
            return
        s.target, s.group = t, tg
        tg.begin(t)
        s.closer = lambda: self._close(s)
        t.closers.add(s.closer)
        s.ready = True
        for d in s.pending:
            s.transport.sendto(d)
        s.pending.clear()

    def _close(self, s: _Session) -> None:
        if self.sessions.get(s.client) is s:
            del self.sessions[s.client]
            self.rt.metrics.udp_sessions.set(self.lb, self.name, value=len(self.sessions))
        if s.transport:
            s.transport.close()
            s.transport = None
        if s.target is not None:
            s.target.closers.discard(s.closer)
            s.group.end(s.target)
            s.target = s.group = s.closer = None

    async def _sweep(self) -> None:
        while True:
            idle = self.spec.timeouts.idle
            await asyncio.sleep(min(max(idle / 4, 0.05), 5.0))
            cutoff = time.monotonic() - idle
            for s in [s for s in self.sessions.values() if s.last < cutoff]:
                self._close(s)
