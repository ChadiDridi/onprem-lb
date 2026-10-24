import os
import signal
import subprocess
import sys
import time
import urllib.request

import yaml
from conftest import free_port


def wait_http(url, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as r:
                return r.status, r.read().decode(), dict(r.headers)
        except OSError:
            time.sleep(0.1)
    raise AssertionError(f"{url} never answered")


def test_serve_reload_and_shutdown(tmp_path):
    port, admin = free_port(), free_port()

    def write(status_body):
        cfg = {
            "admin": {"listen": f"127.0.0.1:{admin}"},
            "load_balancers": {
                "x": {
                    "type": "application",
                    "listeners": [
                        {
                            "port": port,
                            "bind": "127.0.0.1",
                            "protocol": "http",
                            "default_action": {"fixed_response": {"status": 200, "body": status_body}},
                        }
                    ],
                }
            },
        }
        (tmp_path / "lb.yaml").write_text(yaml.safe_dump(cfg))

    write("v1")
    assert subprocess.run(
        [sys.executable, "-m", "onprem_lb", "validate", "-c", str(tmp_path / "lb.yaml")], capture_output=True, text=True
    ).stdout.startswith("ok: 1 load balancer")
    proc = subprocess.Popen(
        [sys.executable, "-m", "onprem_lb", "serve", "-c", str(tmp_path / "lb.yaml"), "--shutdown-grace", "1"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        assert wait_http(f"http://127.0.0.1:{admin}/healthz")[0] == 200
        assert wait_http(f"http://127.0.0.1:{port}/")[1] == "v1"
        write("v2")
        os.kill(proc.pid, signal.SIGHUP)
        deadline = time.time() + 5
        while wait_http(f"http://127.0.0.1:{port}/")[1] != "v2":
            assert time.time() < deadline, "reload not applied"
            time.sleep(0.1)
        # A broken file on reload keeps the running config.
        (tmp_path / "lb.yaml").write_text("load_balancers: {x: {type: bogus}}")
        os.kill(proc.pid, signal.SIGHUP)
        time.sleep(0.5)
        assert wait_http(f"http://127.0.0.1:{port}/")[1] == "v2"
        proc.send_signal(signal.SIGTERM)
        out, _ = proc.communicate(timeout=10)
        assert proc.returncode == 0, out
        assert "reload failed, keeping current config" in out
    finally:
        if proc.poll() is None:
            proc.kill()
