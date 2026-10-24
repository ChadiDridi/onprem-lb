"""Runtime target groups: health state, active counts, draining."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import ssl
import time
from collections.abc import Callable

from . import algorithms, config
from .algorithms import PickContext
from .metrics import Registry

log = logging.getLogger("onprem_lb.targets")

INITIAL = "initial"
HEALTHY = "healthy"
UNHEALTHY = "unhealthy"
DRAINING = "draining"

PASSIVE_FAILURES = 3  # consecutive connect failures before ejection
PASSIVE_EJECT_SECONDS = 10.0


class Target:
    def __init__(self, spec: config.Target, state: str) -> None:
        self.spec = spec
        self.state = state
        self.active = 0
        self.total = 0
        self.ewma = 0.0
        self.samples = 0
        self.ok_streak = 0
        self.fail_streak = 0
        self.last_check = ""
        self.passive_failures = 0
        self.ejected_until = 0.0
        self.closers: set[Callable[[], None]] = set()
        self.sticky_id = hashlib.blake2b(spec.address.encode(), digest_size=8).hexdigest()

    address = property(lambda self: self.spec.address)
    host = property(lambda self: self.spec.host)
    port = property(lambda self: self.spec.port)
    weight = property(lambda self: self.spec.weight)

    @property
    def routable(self) -> bool:
        return self.state == HEALTHY and self.spec.weight > 0 and time.monotonic() >= self.ejected_until

    def observe(self, seconds: float) -> None:
        """Feed a response time into the EWMA used by least_response_time."""
        self.ewma = seconds if self.samples == 0 else 0.7 * self.ewma + 0.3 * seconds
        self.samples += 1

    def connect_ok(self) -> None:
        self.passive_failures = 0

    def connect_failed(self) -> None:
        self.passive_failures += 1
        if self.passive_failures >= PASSIVE_FAILURES:
            self.passive_failures = 0
            self.ejected_until = time.monotonic() + PASSIVE_EJECT_SECONDS
            log.warning("target %s ejected for %.0fs after %d connect failures", self.address, PASSIVE_EJECT_SECONDS, PASSIVE_FAILURES)

    def snapshot(self) -> dict:
        return {
            "address": self.address,
            "weight": self.weight,
            "state": self.state,
            "routable": self.routable,
            "active": self.active,
            "total": self.total,
            "ewma_ms": round(self.ewma * 1000, 3),
            "last_check": self.last_check,
            "ejected": time.monotonic() < self.ejected_until,
        }


class TargetGroup:
    def __init__(self, spec: config.TargetGroup, metrics: Registry) -> None:
        self.spec = spec
        self.metrics = metrics
        self.targets: dict[str, Target] = {}
        self.draining: dict[str, Target] = {}
        self.balancer = algorithms.new(spec.algorithm)
        self._health: asyncio.Task | None = None
        self._drains: set[asyncio.Task] = set()
        self.upstream_ssl: ssl.SSLContext | None = None
        self._apply_targets(spec)
        self._set_upstream_ssl()

    # ---------------------------------------------------------------- lifecycle

    @property
    def checks(self) -> bool:
        return self.spec.health_check.protocol != "none"

    def start(self) -> None:
        if self.checks and self._health is None:
            self._health = asyncio.create_task(self._health_loop(), name=f"health:{self.spec.name}")

    async def stop(self) -> None:
        tasks = [t for t in [self._health, *self._drains] if t]
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._health = None
        for t in list(self.targets.values()) + list(self.draining.values()):
            self.metrics.target_healthy.remove(self.spec.name, t.address)
            self.metrics.target_active.remove(self.spec.name, t.address)

    def update(self, spec: config.TargetGroup) -> None:
        """Apply a new spec in place, keeping state of unchanged targets."""
        old = self.spec
        self.spec = spec
        if spec.algorithm != old.algorithm:
            self.balancer = algorithms.new(spec.algorithm)
        self._apply_targets(spec)
        if spec.tls != old.tls or spec.tls_verify != old.tls_verify:
            self._set_upstream_ssl()
        if spec.health_check != old.health_check:
            if self._health:
                self._health.cancel()
                self._health = None
            if not self.checks:
                for t in self.targets.values():
                    t.state = HEALTHY
            else:
                self.start()

    def _set_upstream_ssl(self) -> None:
        if not self.spec.tls:
            self.upstream_ssl = None
            return
        ctx = ssl.create_default_context()
        if not self.spec.tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.upstream_ssl = ctx

    def _apply_targets(self, spec: config.TargetGroup) -> None:
        want = {t.address: t for t in spec.targets}
        for addr, t in list(self.targets.items()):
            if addr not in want:
                self._drain(t)
            else:
                t.spec = want[addr]
        for addr, ts in want.items():
            if addr in self.targets:
                continue
            if addr in self.draining:  # re-registered while draining
                t = self.draining.pop(addr)
                t.spec = ts
                t.state = INITIAL if self.checks else HEALTHY
            else:
                t = Target(ts, INITIAL if self.checks else HEALTHY)
            self.targets[addr] = t
        self._publish()

    def _drain(self, t: Target) -> None:
        del self.targets[t.address]
        t.state = DRAINING
        self.draining[t.address] = t
        if _loop_running():
            task = asyncio.get_running_loop().create_task(self._drain_wait(t))
            self._drains.add(task)
            task.add_done_callback(self._drains.discard)
        log.info("target %s draining (delay %.0fs, %d active)", t.address, self.spec.deregistration_delay, t.active)

    async def _drain_wait(self, t: Target) -> None:
        deadline = time.monotonic() + self.spec.deregistration_delay
        while t.active > 0 and time.monotonic() < deadline:
            await asyncio.sleep(0.2)
        for close in list(t.closers):
            close()
        if self.draining.get(t.address) is t:
            del self.draining[t.address]
        self.metrics.target_healthy.remove(self.spec.name, t.address)
        self.metrics.target_active.remove(self.spec.name, t.address)
        log.info("target %s deregistered", t.address)

    # ---------------------------------------------------------------- picking

    def routable(self) -> list[Target]:
        return [t for t in self.targets.values() if t.routable]

    def pick(self, ctx: PickContext, exclude: frozenset[str] = frozenset()) -> Target | None:
        cands = [t for t in self.targets.values() if t.routable and t.address not in exclude]
        return self.balancer.pick(cands, ctx)

    def by_sticky_id(self, sid: str) -> Target | None:
        for t in self.targets.values():
            if t.sticky_id == sid and t.routable:
                return t
        return None

    def begin(self, t: Target) -> None:
        t.active += 1
        t.total += 1
        self.metrics.target_active.set(self.spec.name, t.address, value=t.active)

    def end(self, t: Target) -> None:
        t.active -= 1
        self.metrics.target_active.set(self.spec.name, t.address, value=t.active)

    def _publish(self) -> None:
        for t in self.targets.values():
            self.metrics.target_healthy.set(self.spec.name, t.address, value=1 if t.routable else 0)

    def snapshot(self) -> dict:
        return {
            "name": self.spec.name,
            "protocol": self.spec.protocol,
            "algorithm": self.spec.algorithm,
            "targets": [t.snapshot() for t in self.targets.values()],
            "draining": [t.snapshot() for t in self.draining.values()],
        }

    # ---------------------------------------------------------------- health

    async def _health_loop(self) -> None:
        while True:
            hc = self.spec.health_check
            targets = list(self.targets.values())
            results = await asyncio.gather(*(probe(hc, t.host, t.port) for t in targets), return_exceptions=True)
            for t, res in zip(targets, results):
                ok, reason = res if isinstance(res, tuple) else (False, repr(res))
                self._record(t, ok, reason)
            self._publish()
            await asyncio.sleep(hc.interval)

    def _record(self, t: Target, ok: bool, reason: str) -> None:
        if t.state == DRAINING:
            return
        hc = self.spec.health_check
        t.last_check = reason
        before = t.state
        if ok:
            t.ok_streak += 1
            t.fail_streak = 0
            if t.state == INITIAL or (t.state == UNHEALTHY and t.ok_streak >= hc.healthy_threshold):
                t.state = HEALTHY
                t.ejected_until = 0.0
        else:
            t.fail_streak += 1
            t.ok_streak = 0
            if t.state == INITIAL or (t.state == HEALTHY and t.fail_streak >= hc.unhealthy_threshold):
                t.state = UNHEALTHY
        if t.state != before:
            log.warning("target %s in %s: %s -> %s (%s)", t.address, self.spec.name, before, t.state, reason)


def _loop_running() -> bool:
    try:
        asyncio.get_running_loop()
        return True
    except RuntimeError:
        return False


async def probe(hc: config.HealthCheck, host: str, port: int) -> tuple[bool, str]:
    """Run one health check. Returns (ok, reason)."""
    port = hc.port or port
    ctx = None
    if hc.protocol == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), hc.timeout)
    except (TimeoutError, OSError) as e:
        return False, f"connect: {e.__class__.__name__}"
    try:
        if hc.protocol == "tcp":
            return True, "tcp connect ok"
        req = f"GET {hc.path} HTTP/1.1\r\nHost: {hc.host or host}\r\nUser-Agent: onprem-lb-health\r\nConnection: close\r\n\r\n"
        writer.write(req.encode())
        line = await asyncio.wait_for(reader.readline(), hc.timeout)
        parts = line.split(None, 2)
        if len(parts) < 2 or not parts[1].isdigit():
            return False, f"bad status line {line[:40]!r}"
        code = int(parts[1])
        if any(lo <= code <= hi for lo, hi in hc.matcher):
            return True, f"http {code}"
        return False, f"http {code}"
    except (TimeoutError, OSError) as e:
        return False, f"http: {e.__class__.__name__}"
    finally:
        writer.close()
