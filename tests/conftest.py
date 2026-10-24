"""Test helpers: real backends on localhost and a running load balancer."""

from __future__ import annotations

import asyncio
import contextlib
import shutil
import socket
import subprocess
from pathlib import Path

import pytest

from onprem_lb.runtime import Runtime


def free_port(kind: int = socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run(coro, timeout: float = 30):
    async def wrapped():
        return await asyncio.wait_for(coro, timeout)

    return asyncio.run(wrapped())


class TCPEcho:
    """Replies "<name>:" + data for every chunk; records PROXY headers."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.port = free_port()
        self.first_bytes: list[bytes] = []
        self.server = None

    async def start(self):
        self.server = await asyncio.start_server(self._h, "127.0.0.1", self.port)
        return self

    async def _h(self, r, w):
        first = True
        while data := await r.read(65536):
            if first:
                self.first_bytes.append(data)
                first = False
            w.write(self.name.encode() + b":" + data)
            await w.drain()
        # client half-closed: answer once more, then close
        w.write(self.name.encode() + b":eof")
        await w.drain()
        w.close()

    def stop(self):
        self.server.close()


class HTTPBackend:
    """Minimal HTTP/1.1 backend. GET /health returns self.health_status."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.port = free_port()
        self.health_status = 200
        self.delay = 0.0
        self.requests: list[tuple[str, str, dict, bytes]] = []
        self.server = None
        self.connections = 0  # connections that carried a non-health request

    async def start(self):
        self.server = await asyncio.start_server(self._h, "127.0.0.1", self.port)
        return self

    def stop(self):
        self.server.close()

    async def _h(self, r, w):
        counted = False
        try:
            while True:
                head = await r.readuntil(b"\r\n\r\n")
                lines = head.decode().split("\r\n")
                method, target, _ = lines[0].split(" ")
                headers = {}
                for line in lines[1:]:
                    if line:
                        k, _, v = line.partition(":")
                        headers[k.strip().lower()] = v.strip()
                body = b""
                if headers.get("transfer-encoding") == "chunked":
                    while True:
                        size = int((await r.readuntil(b"\r\n")).split(b";")[0], 16)
                        if size == 0:
                            await r.readuntil(b"\r\n")
                            break
                        body += await r.readexactly(size)
                        await r.readexactly(2)
                elif "content-length" in headers:
                    body = await r.readexactly(int(headers["content-length"]))
                self.requests.append((method, target, headers, body))
                if target != "/health" and not counted:
                    counted = True
                    self.connections += 1
                if self.delay:
                    await asyncio.sleep(self.delay)
                if target == "/health":
                    status, payload = self.health_status, b"ok"
                elif target == "/ws" and headers.get("upgrade") == "websocket":
                    w.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                    await w.drain()
                    while data := await r.read(65536):
                        w.write(b"ws-" + self.name.encode() + b":" + data)
                        await w.drain()
                    return
                elif target == "/stream-close":
                    w.write(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + b"x" * 1000 + self.name.encode())
                    await w.drain()
                    w.close()
                    return
                else:
                    status, payload = 200, f"{self.name} {method} {target} len={len(body)}".encode()
                w.write(f"HTTP/1.1 {status} X\r\nContent-Length: {len(payload)}\r\nX-Backend: {self.name}\r\n\r\n".encode() + payload)
                await w.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            w.close()


class UDPEcho(asyncio.DatagramProtocol):
    def __init__(self, name: str) -> None:
        self.name = name
        self.port = free_port(socket.SOCK_DGRAM)

    async def start(self):
        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(lambda: self, local_addr=("127.0.0.1", self.port))
        return self

    def datagram_received(self, data, addr):
        self.transport.sendto(self.name.encode() + b":" + data, addr)

    def stop(self):
        self.transport.close()


async def http(port: int, raw: bytes, ssl=None, server_hostname=None) -> tuple[int, dict, bytes]:
    """Send one raw request on a new connection, read one response."""
    r, w = await asyncio.open_connection("127.0.0.1", port, ssl=ssl, server_hostname=server_hostname)
    try:
        w.write(raw)
        await w.drain()
        return await read_response(r)
    finally:
        w.close()


async def read_response(r) -> tuple[int, dict, bytes]:
    head = await r.readuntil(b"\r\n\r\n")
    lines = head.decode().split("\r\n")
    status = int(lines[0].split(" ")[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if line:
            k, _, v = line.partition(":")
            k = k.strip().lower()
            headers[k] = (headers[k] + ", " + v.strip()) if k in headers else v.strip()
    if headers.get("transfer-encoding") == "chunked":
        body = b""
        while True:
            size = int((await r.readuntil(b"\r\n")).split(b";")[0], 16)
            if size == 0:
                await r.readuntil(b"\r\n")
                break
            body += await r.readexactly(size)
            await r.readexactly(2)
    elif "content-length" in headers:
        body = await r.readexactly(int(headers["content-length"]))
    else:
        body = await r.read()
    return status, headers, body


def get(path: str = "/", host: str = "app.test", extra: str = "") -> bytes:
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra}\r\n".encode()


@contextlib.asynccontextmanager
async def lb(cfg: dict, state_file: str | None = None):
    rt = Runtime(state_file=state_file)
    await rt.apply(cfg)
    try:
        yield rt
    finally:
        await rt.shutdown(0)


async def wait_until(cond, timeout: float = 5.0, step: float = 0.05):
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if cond():
            return
        await asyncio.sleep(step)
    raise AssertionError("condition not met in time")


@pytest.fixture(scope="session")
def certs(tmp_path_factory) -> dict[str, tuple[str, str]]:
    """Self-signed test certificates for a.test and b.test (generated, never committed)."""
    if not shutil.which("openssl"):
        pytest.skip("openssl not available")
    d: Path = tmp_path_factory.mktemp("certs")
    out = {}
    for name in ("a.test", "b.test"):
        crt, key = d / f"{name}.crt", d / f"{name}.key"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                f"/CN={name}",
                "-addext",
                f"subjectAltName=DNS:{name}",
                "-keyout",
                str(key),
                "-out",
                str(crt),
            ],
            check=True,
            capture_output=True,
        )
        out[name] = (str(crt), str(key))
    return out
