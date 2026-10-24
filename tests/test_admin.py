import asyncio
import json
import socket

import pytest
import yaml
from conftest import HTTPBackend, TCPEcho, free_port, get, http, lb, run, wait_until

from onprem_lb.admin import AdminServer


async def api(port, method, path, body=None, token="s3cret"):
    data = json.dumps(body).encode() if body is not None else b""
    auth = f"Authorization: Bearer {token}\r\n" if token else ""
    raw = (f"{method} {path} HTTP/1.1\r\nHost: admin\r\n{auth}Content-Type: application/json\r\nContent-Length: {len(data)}\r\n\r\n").encode() + data
    s, _, out = await http(port, raw)
    return s, (json.loads(out) if out.startswith((b"{", b"[")) else out.decode())


@pytest.fixture
def admin_port():
    return free_port()


def test_create_lb_on_demand_register_and_drain(admin_port):
    async def go():
        b1, b2 = await HTTPBackend("b1").start(), await HTTPBackend("b2").start()
        port = free_port()
        async with lb({}) as rt:
            adm = AdminServer(rt, "s3cret")
            await adm.start("127.0.0.1", admin_port)

            assert (await api(admin_port, "GET", "/healthz", token=None))[0] == 200
            assert (await api(admin_port, "GET", "/config", token=None))[0] == 401
            assert (await api(admin_port, "GET", "/config", token="wrong"))[0] == 401

            # Create a target group and an ALB through the API; traffic flows at once.
            s, _ = await api(
                admin_port,
                "PUT",
                "/target-groups/web",
                {"protocol": "http", "health_check": {"path": "/health", "interval": 0.2, "timeout": 0.1}, "targets": [f"127.0.0.1:{b1.port}"]},
            )
            assert s == 201
            s, _ = await api(
                admin_port,
                "PUT",
                "/load-balancers/site",
                {"type": "application", "listeners": [{"port": port, "bind": "127.0.0.1", "protocol": "http", "default_action": {"forward": "web"}}]},
            )
            assert s == 201
            await wait_until(lambda: rt.groups["web"].routable())
            assert (await http(port, get("/")))[1]["x-backend"] == "b1"

            # Register a second target on demand.
            s, _ = await api(admin_port, "POST", "/target-groups/web/targets", {"address": f"127.0.0.1:{b2.port}", "weight": 1})
            assert s == 201
            assert (await api(admin_port, "POST", "/target-groups/web/targets", {"address": f"127.0.0.1:{b2.port}"}))[0] == 409
            await wait_until(lambda: len(rt.groups["web"].routable()) == 2)
            assert {(await http(port, get("/")))[1]["x-backend"] for _ in range(6)} == {"b1", "b2"}

            # Deregister b1: it drains and stops receiving new requests.
            s, body = await api(admin_port, "DELETE", f"/target-groups/web/targets/127.0.0.1:{b1.port}")
            assert s == 200 and body["deregistered"] == f"127.0.0.1:{b1.port}"
            assert {(await http(port, get("/")))[1]["x-backend"] for _ in range(4)} == {"b2"}

            s, state = await api(admin_port, "GET", "/target-groups/web")
            assert [t["address"] for t in state["status"]["targets"]] == [f"127.0.0.1:{b2.port}"]

            # Delete the LB: the port closes.
            assert (await api(admin_port, "DELETE", "/load-balancers/site"))[0] == 200
            with pytest.raises(OSError):
                await http(port, get("/"))
            await adm.stop()
        b1.stop(), b2.stop()

    run(go())


def test_invalid_change_is_atomic(admin_port):
    async def go():
        a = await TCPEcho("a").start()
        port = free_port()
        cfg = {
            "target_groups": {"t": {"protocol": "tcp", "targets": [f"127.0.0.1:{a.port}"]}},
            "load_balancers": {
                "n": {"type": "network", "listeners": [{"port": port, "bind": "127.0.0.1", "protocol": "tcp", "default_action": {"forward": "t"}}]}
            },
        }
        async with lb(cfg) as rt:
            adm = AdminServer(rt, None)
            await adm.start("127.0.0.1", admin_port)
            before = await api(admin_port, "GET", "/config", token=None)

            # Validation error: nothing changes.
            s, body = await api(admin_port, "DELETE", "/target-groups/t", token=None)
            assert s == 400 and "unknown target group 't'" in body["error"]

            # Runtime error (port already taken): previous config is restored.
            blocker = socket.socket()
            blocker.bind(("127.0.0.1", 0))
            blocker.listen()
            taken = blocker.getsockname()[1]
            s, body = await api(
                admin_port,
                "PUT",
                "/load-balancers/second",
                {"type": "network", "listeners": [{"port": taken, "bind": "127.0.0.1", "protocol": "tcp", "default_action": {"forward": "t"}}]},
                token=None,
            )
            blocker.close()
            assert s == 409
            assert await api(admin_port, "GET", "/config", token=None) == before
            r, w = await asyncio.open_connection("127.0.0.1", port)  # original listener still serves
            w.write(b"x")
            assert await r.read(10) == b"a:x"
            w.close()
            await adm.stop()
        a.stop()

    run(go())


def test_state_file_persists_api_changes(tmp_path, admin_port):
    async def go():
        state = tmp_path / "state.yaml"
        async with lb({}, state_file=str(state)) as rt:
            adm = AdminServer(rt, None)
            await adm.start("127.0.0.1", admin_port)
            await api(admin_port, "PUT", "/target-groups/x", {"protocol": "tcp", "targets": ["10.9.9.9:1"]}, token=None)
            await adm.stop()
        saved = yaml.safe_load(state.read_text())
        assert saved["target_groups"]["x"]["targets"] == ["10.9.9.9:1"]

    run(go())


def test_admin_refuses_public_bind_without_token():
    async def go():
        async with lb({}) as rt:
            with pytest.raises(RuntimeError, match="needs a token"):
                await AdminServer(rt, None).start("0.0.0.0", free_port())

    run(go())


def test_metrics_exposed(admin_port):
    async def go():
        b = await HTTPBackend("b").start()
        port = free_port()
        cfg = {
            "target_groups": {"g": {"protocol": "http", "targets": [f"127.0.0.1:{b.port}"], "health_check": {"protocol": "none"}}},
            "load_balancers": {
                "x": {
                    "type": "application",
                    "listeners": [{"port": port, "bind": "127.0.0.1", "protocol": "http", "default_action": {"forward": "g"}}],
                }
            },
        }
        async with lb(cfg) as rt:
            adm = AdminServer(rt, "s3cret")
            await adm.start("127.0.0.1", admin_port)
            await http(port, get("/"))
            s, text = await api(admin_port, "GET", "/metrics", token=None)
            assert s == 200
            assert f'onprem_lb_http_requests_total{{lb="x",listener="http:{port}",target_group="g",code="2xx"}} 1' in text
            assert "onprem_lb_http_request_duration_seconds_bucket" in text
            await adm.stop()
        b.stop()

    run(go())
