import asyncio
import socket
import ssl

from conftest import TCPEcho, UDPEcho, free_port, lb, run, wait_until

from onprem_lb import proxyproto


def nlb(port, group, protocol="tcp", **listener):
    return {
        "type": "network",
        "listeners": [{"port": port, "bind": "127.0.0.1", "protocol": protocol, "default_action": {"forward": group}, **listener}],
    }


async def tcp_roundtrip(port, payload=b"hi", ssl_ctx=None, server_hostname=None):
    r, w = await asyncio.open_connection("127.0.0.1", port, ssl=ssl_ctx, server_hostname=server_hostname)
    w.write(payload)
    await w.drain()
    data = await r.read(1024)
    w.close()
    return data


def test_tcp_round_robin_and_failover():
    async def go():
        a, b = await TCPEcho("a").start(), await TCPEcho("b").start()
        dead = free_port()  # nothing listens here
        port = free_port()
        cfg = {
            "target_groups": {
                "echo": {
                    "protocol": "tcp",
                    "algorithm": "round_robin",
                    "health_check": {"protocol": "none"},
                    "targets": [f"127.0.0.1:{a.port}", f"127.0.0.1:{dead}", f"127.0.0.1:{b.port}"],
                }
            },
            "load_balancers": {"n": nlb(port, "echo")},
        }
        async with lb(cfg) as rt:
            got = [await tcp_roundtrip(port) for _ in range(6)]
            # The dead target is skipped on connect failure, never surfaced.
            assert {g.split(b":")[0] for g in got} == {b"a", b"b"}
            assert rt.metrics.upstream_errors.values[("echo", "connect")] >= 1
        a.stop(), b.stop()

    run(go())


def test_tcp_half_close_and_proxy_protocol_v2():
    async def go():
        a = await TCPEcho("a").start()
        port = free_port()
        cfg = {
            "target_groups": {"pp": {"protocol": "tcp", "proxy_protocol": "v2", "targets": [f"127.0.0.1:{a.port}"]}},
            "load_balancers": {"n": nlb(port, "pp")},
        }
        async with lb(cfg) as rt:
            await wait_until(lambda: rt.groups["pp"].routable())
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"req")
            await w.drain()
            w.write_eof()  # half-close: backend still answers after our EOF
            data = await r.read()
            w.close()
            assert data.endswith(b"a:eof")
            first = a.first_bytes[0]
            assert first.startswith(proxyproto.V2_SIGNATURE)
            assert first[16:20] == bytes([127, 0, 0, 1])  # client address reached the backend
        a.stop()

    run(go())


def test_health_check_removes_dead_target():
    async def go():
        a, b = await TCPEcho("a").start(), await TCPEcho("b").start()
        port = free_port()
        cfg = {
            "target_groups": {
                "echo": {
                    "protocol": "tcp",
                    "health_check": {"interval": 0.2, "timeout": 0.1, "unhealthy_threshold": 1},
                    "targets": [f"127.0.0.1:{a.port}", f"127.0.0.1:{b.port}"],
                }
            },
            "load_balancers": {"n": nlb(port, "echo")},
        }
        async with lb(cfg) as rt:
            g = rt.groups["echo"]
            await wait_until(lambda: len(g.routable()) == 2)
            b.stop()
            await wait_until(lambda: len(g.routable()) == 1)
            got = {(await tcp_roundtrip(port)).split(b":")[0] for _ in range(4)}
            assert got == {b"a"}
            assert g.targets[f"127.0.0.1:{b.port}"].state == "unhealthy"
        a.stop()

    run(go())


def test_udp_sessions_are_sticky():
    async def go():
        a, b = await UDPEcho("a").start(), await UDPEcho("b").start()
        port = free_port(socket.SOCK_DGRAM)
        cfg = {
            "target_groups": {
                "u": {
                    "protocol": "udp",
                    "algorithm": "round_robin",
                    "health_check": {"protocol": "none"},
                    "targets": [f"127.0.0.1:{a.port}", f"127.0.0.1:{b.port}"],
                }
            },
            "load_balancers": {"n": nlb(port, "u", protocol="udp", timeouts={"idle": 0.5})},
        }
        async with lb(cfg) as rt:
            loop = asyncio.get_running_loop()

            async def client(n):
                q: asyncio.Queue = asyncio.Queue()

                class P(asyncio.DatagramProtocol):
                    def datagram_received(self, d, addr):
                        q.put_nowait(d)

                tr, _ = await loop.create_datagram_endpoint(P, remote_addr=("127.0.0.1", port))
                out = []
                for i in range(n):
                    tr.sendto(b"ping%d" % i)
                    out.append(await asyncio.wait_for(q.get(), 2))
                tr.close()
                return out

            c1, c2 = await client(3), await client(3)
            assert len({x.split(b":")[0] for x in c1}) == 1  # same backend per client session
            assert {c1[0].split(b":")[0], c2[0].split(b":")[0]} == {b"a", b"b"}  # sessions spread
            listener = next(iter(rt.listeners.values()))
            await wait_until(lambda: not listener.sessions, timeout=3)  # idle sessions swept
        a.stop(), b.stop()

    run(go())


def test_tls_termination_with_sni(certs):
    async def go():
        a, b = await TCPEcho("a").start(), await TCPEcho("b").start()
        port = free_port()
        cfg = {
            "target_groups": {"t": {"protocol": "tcp", "targets": [f"127.0.0.1:{a.port}"]}},
            "load_balancers": {
                "n": nlb(
                    port,
                    "t",
                    protocol="tls",
                    certificates=[
                        {"cert": certs["a.test"][0], "key": certs["a.test"][1], "server_names": ["a.test"]},
                        {"cert": certs["b.test"][0], "key": certs["b.test"][1], "server_names": ["b.test", "*.b.test"]},
                    ],
                )
            },
        }
        async with lb(cfg) as rt:
            await wait_until(lambda: rt.groups["t"].routable())
            for name in ("a.test", "b.test"):
                ctx = ssl.create_default_context(cafile=certs[name][0])
                assert (await tcp_roundtrip(port, b"x", ctx, name)) == b"a:x"
            # Wrong CA for the name -> handshake fails: SNI picked the b.test cert.
            ctx = ssl.create_default_context(cafile=certs["a.test"][0])
            try:
                await tcp_roundtrip(port, b"x", ctx, "b.test")
                raise AssertionError("expected certificate verification failure")
            except ssl.SSLCertVerificationError:
                pass
        a.stop(), b.stop()

    run(go())
