"""Multi-core mode: a master process and N worker processes.

Workers run the data plane; each binds every listener with SO_REUSEPORT so
the kernel spreads connections (and UDP flows, by 4-tuple) across them. The
master runs the admin API and owns the config: a change goes live only if
every worker applies it, otherwise all workers are rolled back to the previous
config. Crashed workers are respawned with the current config.

Control messages are JSON lines over a socketpair passed to each worker.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import os
import signal
import socket
import sys
from typing import Any

from . import config
from .metrics import Registry
from .runtime import Runtime, persist

log = logging.getLogger("onprem_lb.cluster")


class WorkerError(OSError):
    """A worker failed to apply a config (e.g. a port is in use)."""


class Worker:
    def __init__(self, index: int, log_level: str, access_log: bool, uvloop: bool) -> None:
        self.index = index
        self.args = (log_level, access_log, uvloop)
        self.proc: asyncio.subprocess.Process | None = None
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.lock = asyncio.Lock()

    async def spawn(self) -> None:
        parent, child = socket.socketpair()
        log_level, access_log, uvloop = self.args
        cmd = [sys.executable, "-m", "onprem_lb", "worker", "--control-fd", str(child.fileno()), "--index", str(self.index), "--log-level", log_level]
        if not access_log:
            cmd.append("--no-access-log")
        if not uvloop:
            cmd.append("--no-uvloop")
        self.proc = await asyncio.create_subprocess_exec(*cmd, pass_fds=(child.fileno(),))
        child.close()
        self.reader, self.writer = await asyncio.open_connection(sock=parent)

    async def call(self, msg: dict, timeout: float = 30.0) -> dict:
        async with self.lock:
            self.writer.write(json.dumps(msg).encode() + b"\n")
            await self.writer.drain()
            line = await asyncio.wait_for(self.reader.readline(), timeout)
        if not line:
            raise WorkerError(f"worker {self.index} exited")
        return json.loads(line)


class Cluster:
    """Same interface as Runtime, as used by the admin API and the CLI."""

    def __init__(self, workers: int, state_file: str | None, log_level: str, access_log: bool, uvloop: bool) -> None:
        self.workers = [Worker(i, log_level, access_log, uvloop) for i in range(workers)]
        self.state_file = state_file
        self.raw: dict[str, Any] = {}
        self.config: config.Config | None = None
        self._lock = asyncio.Lock()
        self._stopping = False
        self._monitor: asyncio.Task | None = None

    async def start(self) -> None:
        await asyncio.gather(*(w.spawn() for w in self.workers))
        self._monitor = asyncio.create_task(self._watch())

    async def apply(self, raw: Any) -> config.Config:
        async with self._lock:
            cfg = config.parse(raw)
            results = await asyncio.gather(*(w.call({"op": "apply", "raw": raw}) for w in self.workers), return_exceptions=True)
            errors = [r if isinstance(r, Exception) else r.get("error") for r in results if isinstance(r, Exception) or not r.get("ok")]
            if errors:
                if self.raw:
                    await asyncio.gather(*(w.call({"op": "apply", "raw": self.raw}) for w in self.workers), return_exceptions=True)
                raise WorkerError(f"{len(errors)}/{len(self.workers)} worker(s) failed: {errors[0]}")
            self.raw = copy.deepcopy(raw)
            self.config = cfg
            if self.state_file:
                persist(self.state_file, self.raw)
            return cfg

    async def _gather(self, op: dict) -> list[dict]:
        res = await asyncio.gather(*(w.call(op) for w in self.workers), return_exceptions=True)
        return [r for r in res if isinstance(r, dict)]

    async def metrics_text(self) -> str:
        return Registry.merged([r["metrics"] for r in await self._gather({"op": "metrics"})]).render()

    async def state(self) -> dict:
        snaps = [r["state"] for r in await self._gather({"op": "state"})]
        listeners: dict[tuple, dict] = {}
        for s in snaps:
            for ls in s["listeners"]:
                key = (ls["load_balancer"], ls["bind"], ls["port"], ls["protocol"])
                cur = listeners.setdefault(key, {**ls, "connections": 0})
                cur["connections"] += ls["connections"]
        groups = {}
        for name in self.raw.get("target_groups") or {}:
            groups[name] = _merge_groups([s["target_groups"].get(name) for s in snaps])
        return {"workers": len(self.workers), "listeners": list(listeners.values()), "target_groups": groups}

    async def group_state(self, name: str) -> dict | None:
        res = await self._gather({"op": "group", "name": name})
        return _merge_groups([r.get("group") for r in res])

    async def shutdown(self, grace: float) -> None:
        self._stopping = True
        if self._monitor:
            self._monitor.cancel()
        await asyncio.gather(*(w.call({"op": "shutdown", "grace": grace}, timeout=grace + 10) for w in self.workers), return_exceptions=True)
        for w in self.workers:
            if w.proc and w.proc.returncode is None:
                try:
                    await asyncio.wait_for(w.proc.wait(), 5)
                except TimeoutError:
                    w.proc.kill()

    async def _watch(self) -> None:
        while True:
            waits = {asyncio.create_task(w.proc.wait()): w for w in self.workers}
            done, pending = await asyncio.wait(waits, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            if self._stopping:
                return
            for t in done:
                w = waits[t]
                log.error("worker %d exited with %s; respawning", w.index, w.proc.returncode)
                await w.spawn()
                if self.raw:
                    async with self._lock:
                        r = await w.call({"op": "apply", "raw": self.raw})
                    if not r.get("ok"):
                        log.error("respawned worker %d could not apply config: %s", w.index, r.get("error"))
                await asyncio.sleep(1)  # avoid a hot crash loop


def _merge_groups(snaps: list[dict | None]) -> dict | None:
    snaps = [s for s in snaps if s]
    if not snaps:
        return None
    out = {k: v for k, v in snaps[0].items() if k not in ("targets", "draining")}
    for kind in ("targets", "draining"):
        merged: dict[str, dict] = {}
        for s in snaps:
            for t in s[kind]:
                cur = merged.get(t["address"])
                if cur is None:
                    merged[t["address"]] = {**t, "routable_workers": int(t["routable"])}
                    continue
                cur["active"] += t["active"]
                cur["total"] += t["total"]
                cur["routable_workers"] += int(t["routable"])
                cur["routable"] = cur["routable"] or t["routable"]
        out[kind] = list(merged.values())
    return out


# ------------------------------------------------------------------- worker side


async def worker_main(control_fd: int, index: int) -> int:
    signal.signal(signal.SIGINT, signal.SIG_IGN)  # the master coordinates shutdown
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    sock = socket.socket(fileno=control_fd)
    reader, writer = await asyncio.open_connection(sock=sock)
    rt = Runtime(reuse_port=True)
    log.info("worker %d (pid %d) ready", index, os.getpid())

    def reply(msg: dict) -> None:
        writer.write(json.dumps(msg, default=str).encode() + b"\n")

    while True:
        line = await reader.readline()
        if not line:  # master is gone
            await rt.shutdown(0)
            return 0
        msg = json.loads(line)
        op = msg.get("op")
        try:
            if op == "apply":
                await rt.apply(msg["raw"])
                reply({"ok": True})
            elif op == "metrics":
                reply({"metrics": rt.metrics.dump()})
            elif op == "state":
                reply({"state": rt.snapshot()})
            elif op == "group":
                reply({"group": await rt.group_state(msg["name"])})
            elif op == "shutdown":
                await rt.shutdown(float(msg.get("grace", 0)))
                reply({"ok": True})
                await writer.drain()
                return 0
            else:
                reply({"ok": False, "error": f"unknown op {op!r}"})
        except Exception as e:  # noqa: BLE001 - report to the master instead of dying
            reply({"ok": False, "error": f"{e.__class__.__name__}: {e}"})
        await writer.drain()
