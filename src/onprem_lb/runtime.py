"""Applies configs live: diffs target groups and listeners against what runs.

Every change (file, SIGHUP, admin API) goes through ``apply``: the whole new
config is validated first, then applied as a diff. Unchanged listeners keep
their sockets and connections; target groups keep target health and counters.
If anything fails mid-way (e.g. a port is taken) the previous config is
re-applied.
"""

from __future__ import annotations

import asyncio
import copy
import logging
import os
import tempfile
from typing import Any

import yaml

from . import config
from .http.proxy import HTTPListener, Pool
from .l4 import TCPListener, UDPListener
from .metrics import Registry
from .targets import TargetGroup

log = logging.getLogger("onprem_lb.runtime")

AnyListener = TCPListener | UDPListener | HTTPListener
ListenerKey = tuple[str, str, int, str]  # lb, bind, port, protocol


def _make_listener(lb: str, spec: config.Listener, rt: Runtime) -> AnyListener:
    if spec.protocol in ("http", "https"):
        return HTTPListener(lb, spec, rt)
    if spec.protocol == "udp":
        return UDPListener(lb, spec, rt)
    return TCPListener(lb, spec, rt)


class Runtime:
    def __init__(self, state_file: str | None = None, reuse_port: bool = False) -> None:
        self.reuse_port = reuse_port  # workers share listening ports (SO_REUSEPORT)
        self.metrics = Registry()
        self.groups: dict[str, TargetGroup] = {}
        self.listeners: dict[ListenerKey, AnyListener] = {}
        self.pool = Pool()
        self.raw: dict[str, Any] = {}
        self.config: config.Config | None = None
        self.state_file = state_file
        self._lock = asyncio.Lock()

    async def apply(self, raw: Any) -> config.Config:
        """Validate and apply a complete config. Raises ConfigError or OSError."""
        async with self._lock:
            cfg = config.parse(raw)  # nothing changes if this raises
            previous = self.raw
            try:
                await self._apply(cfg)
            except Exception:
                self.metrics.config_reloads.inc("error")
                if previous:
                    log.error("apply failed; restoring previous config")
                    await self._apply(config.parse(previous))
                raise
            self.raw = copy.deepcopy(raw)
            self.config = cfg
            self.metrics.config_reloads.inc("ok")
            self._persist()
            return cfg

    async def _apply(self, cfg: config.Config) -> None:
        # 1. Target groups: create or update in place (listeners resolve
        #    groups by name per connection, so new ones must exist first).
        for name, spec in cfg.target_groups.items():
            if name in self.groups:
                self.groups[name].update(spec)
            else:
                g = TargetGroup(spec, self.metrics)
                self.groups[name] = g
                g.start()

        # 2. Listeners: stop removed ones first so their ports free up.
        desired: dict[ListenerKey, tuple[str, config.Listener]] = {}
        for lb in cfg.load_balancers.values():
            for ls in lb.listeners:
                desired[(lb.name, ls.bind, ls.port, ls.protocol)] = (lb.name, ls)
        for key in [k for k in self.listeners if k not in desired]:
            await self.listeners.pop(key).stop()
            log.info("listener %s stopped", key)
        for key, (lb, ls) in desired.items():
            if key in self.listeners:
                self.listeners[key].update(ls)
                continue
            listener = _make_listener(lb, ls, self)
            await listener.start()  # may raise OSError (port in use)
            self.listeners[key] = listener
            log.info("listener %s/%s %s:%d started", lb, ls.protocol, ls.bind, ls.port)

        # 3. Groups nobody references any more.
        for name in [n for n in self.groups if n not in cfg.target_groups]:
            await self.groups.pop(name).stop()

    async def shutdown(self, grace: float) -> None:
        async with self._lock:
            await asyncio.gather(*(ls.stop(grace) for ls in self.listeners.values()), return_exceptions=True)
            self.listeners.clear()
            for g in self.groups.values():
                await g.stop()
            self.groups.clear()
            self.pool.close_all()

    def _persist(self) -> None:
        if self.state_file:
            persist(self.state_file, self.raw)

    # Interface used by the admin API (shared with cluster.Cluster).

    async def state(self) -> dict:
        return self.snapshot()

    async def metrics_text(self) -> str:
        return self.metrics.render()

    async def group_state(self, name: str) -> dict | None:
        g = self.groups.get(name)
        return g.snapshot() if g else None

    def snapshot(self) -> dict:
        return {
            "listeners": [
                {
                    "load_balancer": k[0],
                    "bind": k[1],
                    "port": k[2],
                    "protocol": k[3],
                    "connections": len(getattr(ls, "clients", ())) or len(getattr(ls, "sessions", ())),
                }
                for k, ls in sorted(self.listeners.items())
            ],
            "target_groups": {n: g.snapshot() for n, g in sorted(self.groups.items())},
        }


def persist(path: str, raw: dict) -> None:
    """Write the live config atomically."""
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".onprem-lb-", dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            yaml.safe_dump(raw, f, sort_keys=False)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise
