import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.request

import pytest
import yaml
from conftest import free_port
from test_cli import wait_http


def call(url, method="GET", body=None):
    req = urllib.request.Request(
        url, method=method, data=json.dumps(body).encode() if body is not None else None, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def worker_pids(master_pid):
    out = subprocess.run(["ps", "-o", "pid=", "--ppid", str(master_pid)], capture_output=True, text=True).stdout
    return sorted(int(p) for p in out.split())


@pytest.mark.skipif(not hasattr(socket, "SO_REUSEPORT"), reason="needs SO_REUSEPORT")
def test_workers_share_ports_apply_atomically_and_respawn(tmp_path):
    port, admin = free_port(), free_port()
    cfg = {
        "admin": {"listen": f"127.0.0.1:{admin}"},
        "load_balancers": {
            "x": {
                "type": "application",
                "listeners": [
                    {"port": port, "bind": "127.0.0.1", "protocol": "http", "default_action": {"fixed_response": {"status": 200, "body": "v1"}}}
                ],
            }
        },
    }
    (tmp_path / "lb.yaml").write_text(yaml.safe_dump(cfg))
    proc = subprocess.Popen(
        [sys.executable, "-m", "onprem_lb", "serve", "-c", str(tmp_path / "lb.yaml"), "--workers", "3", "--shutdown-grace", "1"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    base = f"http://127.0.0.1:{admin}"
    try:
        wait_http(f"{base}/healthz")
        assert len(worker_pids(proc.pid)) == 3
        for _ in range(30):
            assert wait_http(f"http://127.0.0.1:{port}/")[1] == "v1"

        # Metrics are merged across workers: every request is counted once.
        text = call(f"{base}/metrics")[1]
        conns = sum(float(v) for v in re.findall(r'onprem_lb_connections_total\{lb="x".*\} (\S+)', text))
        assert conns == 30
        assert json.loads(call(f"{base}/state")[1])["workers"] == 3

        # An API change reaches every worker.
        lb = cfg["load_balancers"]["x"]
        lb["listeners"][0]["default_action"] = {"fixed_response": {"status": 200, "body": "v2"}}
        assert call(f"{base}/load-balancers/x", "PUT", lb)[0] == 200
        assert {wait_http(f"http://127.0.0.1:{port}/")[1] for _ in range(30)} == {"v2"}

        # A port conflict in the workers rolls everything back.
        blocker = socket.socket()
        blocker.bind(("127.0.0.1", 0))
        blocker.listen()
        taken = blocker.getsockname()[1]
        status, body = call(
            f"{base}/load-balancers/y",
            "PUT",
            {
                "type": "application",
                "listeners": [{"port": taken, "bind": "127.0.0.1", "protocol": "http", "default_action": {"fixed_response": {"status": 200}}}],
            },
        )
        blocker.close()
        assert status == 409 and "worker(s) failed" in body
        assert "y" not in json.loads(call(f"{base}/config")[1])["load_balancers"]

        # A crashed worker is respawned with the current config.
        victim = worker_pids(proc.pid)[0]
        os.kill(victim, signal.SIGKILL)
        deadline = time.time() + 10
        while not (len(pids := worker_pids(proc.pid)) == 3 and victim not in pids):
            assert time.time() < deadline, "worker not respawned"
            time.sleep(0.2)
        time.sleep(0.5)
        assert {wait_http(f"http://127.0.0.1:{port}/")[1] for _ in range(30)} == {"v2"}

        proc.send_signal(signal.SIGTERM)
        out, _ = proc.communicate(timeout=20)
        assert proc.returncode == 0, out
        assert "respawning" in out
    finally:
        if proc.poll() is None:
            proc.kill()
