import asyncio
import ssl

from conftest import HTTPBackend, free_port, get, http, lb, read_response, run, wait_until


def alb(port, default, rules=(), protocol="http", **listener):
    return {
        "type": "application",
        "listeners": [{"port": port, "bind": "127.0.0.1", "protocol": protocol, "default_action": default, "rules": list(rules), **listener}],
    }


def group(*backends, **kw):
    hc = kw.pop("health_check", {"path": "/health", "interval": 0.2, "timeout": 0.1, "unhealthy_threshold": 1, "healthy_threshold": 1})
    return {"protocol": "http", "health_check": hc, "targets": [f"127.0.0.1:{b.port}" for b in backends], **kw}


async def ready(rt, *names):
    for n in names:
        g = rt.groups[n]
        await wait_until(lambda g=g: len(g.routable()) == len(g.targets))


def test_routing_rules_actions_and_headers():
    async def go():
        api, web = await HTTPBackend("api").start(), await HTTPBackend("web").start()
        port = free_port()
        cfg = {
            "target_groups": {"api": group(api), "web": group(web)},
            "load_balancers": {
                "x": alb(
                    port,
                    {"forward": "web"},
                    rules=[
                        {"priority": 1, "conditions": {"host": ["api.test"]}, "action": {"forward": "api"}},
                        {
                            "priority": 2,
                            "conditions": {"path": ["/old/*"]},
                            "action": {"redirect": {"status": 308, "location": "http://{host}/new{path}"}},
                        },
                        {
                            "priority": 3,
                            "conditions": {"path": ["/maint"]},
                            "action": {"fixed_response": {"status": 503, "body": "down", "headers": {"Retry-After": "30"}}},
                        },
                    ],
                )
            },
        }
        async with lb(cfg) as rt:
            await ready(rt, "api", "web")
            s, h, body = await http(port, get("/x", host="api.test"))
            assert s == 200 and body.startswith(b"api GET /x")
            s, h, body = await http(port, get("/x", host="www.test", extra="X-Forwarded-For: 1.2.3.4\r\n"))
            assert body.startswith(b"web")
            fwd = web.requests[-1][2]
            assert fwd["x-forwarded-for"] == "1.2.3.4, 127.0.0.1"
            assert fwd["x-forwarded-proto"] == "http" and fwd["x-forwarded-port"] == str(port)
            assert len(fwd["x-request-id"]) == 32
            s, h, _ = await http(port, get("/old/a", host="www.test"))
            assert s == 308 and h["location"] == "http://www.test/new/old/a"
            s, h, body = await http(port, get("/maint"))
            assert (s, body, h["retry-after"]) == (503, b"down", "30")
        api.stop(), web.stop()

    run(go())


def test_keepalive_and_upstream_pool_reuse():
    async def go():
        b = await HTTPBackend("b").start()
        port = free_port()
        cfg = {"target_groups": {"g": group(b)}, "load_balancers": {"x": alb(port, {"forward": "g"})}}
        async with lb(cfg) as rt:
            await ready(rt, "g")
            before = b.connections
            r, w = await asyncio.open_connection("127.0.0.1", port)
            for i in range(5):
                w.write(get(f"/{i}"))
                s, _, body = await read_response(r)
                assert s == 200 and body.startswith(f"b GET /{i}".encode())
            w.close()
            # 5 requests on one client connection reused one upstream connection.
            assert b.connections - before == 1
        b.stop()

    run(go())


def test_bodies_chunked_and_close_delimited():
    async def go():
        b = await HTTPBackend("b").start()
        port = free_port()
        cfg = {"target_groups": {"g": group(b)}, "load_balancers": {"x": alb(port, {"forward": "g"})}}
        async with lb(cfg) as rt:
            await ready(rt, "g")
            chunked = b"POST /up HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
            s, _, body = await http(port, chunked)
            assert body == b"b POST /up len=11" and b.requests[-1][3] == b"hello world"
            s, _, body = await http(port, b"POST /cl HTTP/1.1\r\nHost: t\r\nContent-Length: 3\r\n\r\nabc")
            assert body == b"b POST /cl len=3"
            # Close-delimited upstream body is re-chunked for an HTTP/1.1 client.
            s, h, body = await http(port, get("/stream-close"))
            assert h.get("transfer-encoding") == "chunked" and body.endswith(b"b") and len(body) == 1001
            # Expect: 100-continue is answered by the LB.
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"POST /e HTTP/1.1\r\nHost: t\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n")
            assert (await r.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 100")
            w.write(b"ok")
            s, _, body = await read_response(r)
            assert body == b"b POST /e len=2" and "expect" not in b.requests[-1][2]
            w.close()
        b.stop()

    run(go())


def test_smuggling_attempt_rejected():
    async def go():
        b = await HTTPBackend("b").start()
        port = free_port()
        cfg = {"target_groups": {"g": group(b)}, "load_balancers": {"x": alb(port, {"forward": "g"})}}
        async with lb(cfg) as rt:
            await ready(rt, "g")
            n = len(b.requests)
            raw = (
                b"POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"0\r\n\r\nGET /admin HTTP/1.1\r\nHost: t\r\n\r\n"
            )
            s, _, _ = await http(port, raw)
            assert s == 400 and len(b.requests) == n  # nothing reached the backend
        b.stop()

    run(go())


def test_sticky_cookie_and_weighted_forward():
    async def go():
        bs = [await HTTPBackend(f"b{i}").start() for i in range(3)]
        port = free_port()
        cfg = {
            "target_groups": {"g": group(*bs, algorithm="round_robin", stickiness={"enabled": True, "cookie": "lb"})},
            "load_balancers": {"x": alb(port, {"forward": "g"})},
        }
        async with lb(cfg) as rt:
            await ready(rt, "g")
            s, h, body = await http(port, get("/"))
            cookie = h["set-cookie"].split(";")[0]
            first = h["x-backend"]
            for _ in range(5):
                s, h2, _ = await http(port, get("/", extra=f"Cookie: {cookie}\r\n"))
                assert h2["x-backend"] == first and "set-cookie" not in h2
        for b in bs:
            b.stop()

    run(go())


def test_weighted_target_groups_canary():
    async def go():
        stable, canary = await HTTPBackend("stable").start(), await HTTPBackend("canary").start()
        port = free_port()
        cfg = {
            "target_groups": {"s": group(stable), "c": group(canary)},
            "load_balancers": {"x": alb(port, {"forward": [{"target_group": "s", "weight": 4}, {"target_group": "c", "weight": 1}]})},
        }
        async with lb(cfg) as rt:
            await ready(rt, "s", "c")
            got = [(await http(port, get("/")))[1]["x-backend"] for _ in range(200)]
            share = got.count("canary") / len(got)
            assert 0.1 < share < 0.32  # 20% expected
        stable.stop(), canary.stop()

    run(go())


def test_failures_map_to_502_503_504_and_health_shifts_traffic():
    async def go():
        good, bad = await HTTPBackend("good").start(), await HTTPBackend("bad").start()
        slow = await HTTPBackend("slow").start()
        port, port_slow = free_port(), free_port()
        cfg = {
            "target_groups": {
                "g": group(good, bad, algorithm="round_robin"),
                "slow": group(slow),
                "empty": {"protocol": "http", "targets": []},
            },
            "load_balancers": {
                "x": alb(port, {"forward": "g"}, rules=[{"priority": 1, "conditions": {"path": ["/empty"]}, "action": {"forward": "empty"}}]),
                "y": alb(port_slow, {"forward": "slow"}, timeouts={"response": 0.3}),
            },
        }
        async with lb(cfg) as rt:
            await ready(rt, "g", "slow")
            assert (await http(port, get("/empty")))[0] == 503
            bad.health_status = 500
            await wait_until(lambda: len(rt.groups["g"].routable()) == 1)
            assert {(await http(port, get("/")))[1]["x-backend"] for _ in range(6)} == {"good"}
            slow.delay = 1.0
            assert (await http(port_slow, get("/")))[0] == 504
            good.stop()
            await wait_until(lambda: not rt.groups["g"].routable())
            assert (await http(port, get("/")))[0] == 503
        bad.stop(), slow.stop()

    run(go())


def test_websocket_upgrade_tunnel():
    async def go():
        b = await HTTPBackend("b").start()
        port = free_port()
        cfg = {"target_groups": {"g": group(b)}, "load_balancers": {"x": alb(port, {"forward": "g"})}}
        async with lb(cfg) as rt:
            await ready(rt, "g")
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"GET /ws HTTP/1.1\r\nHost: t\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
            head = await r.readuntil(b"\r\n\r\n")
            assert head.startswith(b"HTTP/1.1 101") and b"Upgrade: websocket" in head
            w.write(b"frame1")
            assert await r.read(100) == b"ws-b:frame1"
            w.close()
        b.stop()

    run(go())


def test_https_listener(certs):
    async def go():
        b = await HTTPBackend("b").start()
        port = free_port()
        cfg = {
            "target_groups": {"g": group(b)},
            "load_balancers": {
                "x": alb(port, {"forward": "g"}, protocol="https", certificates=[{"cert": certs["a.test"][0], "key": certs["a.test"][1]}])
            },
        }
        async with lb(cfg) as rt:
            await ready(rt, "g")
            ctx = ssl.create_default_context(cafile=certs["a.test"][0])
            s, _, body = await http(port, get("/s", host="a.test"), ssl=ctx, server_hostname="a.test")
            assert s == 200 and b.requests[-1][2]["x-forwarded-proto"] == "https"
        b.stop()

    run(go())


def test_hash_by_header_is_consistent():
    async def go():
        bs = [await HTTPBackend(f"b{i}").start() for i in range(4)]
        port = free_port()
        cfg = {
            "target_groups": {"g": group(*bs, algorithm="consistent_hash", hash_key="header:X-User")},
            "load_balancers": {"x": alb(port, {"forward": "g"})},
        }
        async with lb(cfg) as rt:
            await ready(rt, "g")
            seen = {}
            for u in range(20):
                for _ in range(2):
                    be = (await http(port, get("/", extra=f"X-User: u{u}\r\n")))[1]["x-backend"]
                    assert seen.setdefault(u, be) == be
            assert len(set(seen.values())) > 1
        for b in bs:
            b.stop()

    run(go())
