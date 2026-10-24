"""Load balancing algorithms.

Every balancer picks from the *routable* targets it is given (healthy, not
draining, weight > 0). Hash-based balancers build their structure over that
set and cache it until the set changes, so a target going unhealthy only moves
the keys that were on it.

Hashes use blake2b, not Python's hash(), so placement is stable across
processes and restarts.
"""

from __future__ import annotations

import bisect
import hashlib
import itertools
import random
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol


class Candidate(Protocol):
    address: str
    weight: int
    active: int
    ewma: float  # smoothed response time in seconds


@dataclass
class PickContext:
    client_ip: str = ""
    client_port: int = 0
    key: str | None = None  # hash key value (header, cookie, uri, ...); None = use client_ip


def stable_hash(s: str) -> int:
    return int.from_bytes(hashlib.blake2b(s.encode(), digest_size=8).digest(), "big")


class Balancer:
    name = ""

    def pick(self, cands: Sequence[Candidate], ctx: PickContext) -> Candidate | None:
        raise NotImplementedError


class RoundRobin(Balancer):
    name = "round_robin"

    def __init__(self) -> None:
        self._n = itertools.count()

    def pick(self, cands, ctx):
        if not cands:
            return None
        return cands[next(self._n) % len(cands)]


class WeightedRoundRobin(Balancer):
    """Smooth weighted round robin (nginx): spreads heavy targets out instead
    of sending them consecutive bursts."""

    name = "weighted_round_robin"

    def __init__(self) -> None:
        self._current: dict[str, int] = {}

    def pick(self, cands, ctx):
        if not cands:
            return None
        total = 0
        best = None
        for c in cands:
            cur = self._current.get(c.address, 0) + c.weight
            self._current[c.address] = cur
            total += c.weight
            if best is None or cur > self._current[best.address]:
                best = c
        self._current[best.address] -= total
        if len(self._current) > 4 * len(cands):  # forget removed targets
            live = {c.address for c in cands}
            self._current = {k: v for k, v in self._current.items() if k in live}
        return best


class LeastConnections(Balancer):
    """Fewest active connections/requests; ties rotate so equal targets share."""

    name = "least_connections"
    weighted = False

    def __init__(self) -> None:
        self._n = itertools.count()

    def pick(self, cands, ctx):
        if not cands:
            return None
        start = next(self._n) % len(cands)
        best = None
        best_score = 0.0
        for i in range(len(cands)):
            c = cands[(start + i) % len(cands)]
            score = c.active / c.weight if self.weighted else c.active
            if best is None or score < best_score:
                best, best_score = c, score
        return best


class WeightedLeastConnections(LeastConnections):
    name = "weighted_least_connections"
    weighted = True


class Random(Balancer):
    name = "random"

    def __init__(self, rng: random.Random | None = None) -> None:
        self._rng = rng or random.Random()

    def pick(self, cands, ctx):
        return self._rng.choice(cands) if cands else None


class WeightedRandom(Random):
    name = "weighted_random"

    def pick(self, cands, ctx):
        if not cands:
            return None
        return self._rng.choices(cands, weights=[c.weight for c in cands])[0]


class PowerOfTwo(Random):
    """Power of two choices: sample two targets (by weight), take the one with
    fewer active connections. Near least-connections quality at O(1)."""

    name = "power_of_two"

    def pick(self, cands, ctx):
        if not cands:
            return None
        if len(cands) == 1:
            return cands[0]
        a, b = self._rng.choices(cands, weights=[c.weight for c in cands], k=2)
        return a if a.active / a.weight <= b.active / b.weight else b


class LeastResponseTime(Balancer):
    """Lowest smoothed response time scaled by load: ewma * (active + 1).
    Targets without samples yet are tried first."""

    name = "least_response_time"

    def __init__(self) -> None:
        self._n = itertools.count()

    def pick(self, cands, ctx):
        if not cands:
            return None
        start = next(self._n) % len(cands)
        best = None
        best_score = 0.0
        for i in range(len(cands)):
            c = cands[(start + i) % len(cands)]
            score = (c.ewma * (c.active + 1)) / c.weight
            if best is None or score < best_score:
                best, best_score = c, score
        return best


def _key(ctx: PickContext) -> str:
    return ctx.key if ctx.key is not None else ctx.client_ip


class _Cached(Balancer):
    """Rebuilds a lookup structure when the candidate set changes."""

    def __init__(self) -> None:
        self._sig: tuple = ()
        self._built = None

    def _structure(self, cands):
        sig = tuple((c.address, c.weight) for c in cands)
        if sig != self._sig:
            self._sig, self._built = sig, self._build(cands)
        return self._built

    def _build(self, cands):
        raise NotImplementedError


class IPHash(_Cached):
    """hash(key) mod N over targets sorted by address (expanded by weight).
    Simple but remaps most keys when N changes; prefer consistent_hash or
    maglev when targets come and go."""

    name = "ip_hash"

    def _build(self, cands):
        slots = []
        for c in sorted(cands, key=lambda c: c.address):
            slots.extend([c] * c.weight)
        return slots

    def pick(self, cands, ctx):
        if not cands:
            return None
        slots = self._structure(cands)
        return slots[stable_hash(_key(ctx)) % len(slots)]


class ConsistentHash(_Cached):
    """Hash ring with virtual nodes (160 per unit of weight, as in ketama).
    Removing a target moves only the keys it owned."""

    name = "consistent_hash"
    VNODES = 160

    def _build(self, cands):
        ring = []
        for c in cands:
            for i in range(self.VNODES * c.weight):
                ring.append((stable_hash(f"{c.address}#{i}"), c))
        ring.sort(key=lambda x: x[0])
        return [h for h, _ in ring], [c for _, c in ring]

    def pick(self, cands, ctx):
        if not cands:
            return None
        hashes, owners = self._structure(cands)
        i = bisect.bisect(hashes, stable_hash(_key(ctx))) % len(hashes)
        return owners[i]


class Maglev(_Cached):
    """Maglev hashing (Eisenbud et al., NSDI 2016): a lookup table of prime
    size M filled from per-target permutations. O(1) lookups, near-even
    spread, minimal disruption on changes. Weights scale fill turns."""

    name = "maglev"
    # Table sizes: primes; the paper wants M >= 100 * N for < 1% imbalance.
    PRIMES = (1009, 5003, 10007, 50021, 100003)

    def _build(self, cands):
        m = next((p for p in self.PRIMES if p >= 100 * len(cands)), self.PRIMES[-1])
        n = len(cands)
        offset = []
        skip = []
        for c in cands:
            h = hashlib.blake2b(c.address.encode(), digest_size=16).digest()
            offset.append(int.from_bytes(h[:8], "big") % m)
            skip.append(int.from_bytes(h[8:], "big") % (m - 1) + 1)
        nxt = [0] * n
        table: list[int] = [-1] * m
        filled = 0
        max_w = max(c.weight for c in cands)
        credit = [0.0] * n
        while True:
            for i in range(n):
                # Weighted Maglev: each round a target gets weight/max_w turns.
                credit[i] += cands[i].weight / max_w
                while credit[i] >= 1:
                    credit[i] -= 1
                    while True:
                        slot = (offset[i] + nxt[i] * skip[i]) % m
                        nxt[i] += 1
                        if table[slot] < 0:
                            break
                    table[slot] = i
                    filled += 1
                    if filled == m:
                        return [cands[j] for j in table]

    def pick(self, cands, ctx):
        if not cands:
            return None
        table = self._structure(cands)
        return table[stable_hash(_key(ctx)) % len(table)]


REGISTRY: dict[str, type[Balancer]] = {
    cls.name: cls
    for cls in (
        RoundRobin,
        WeightedRoundRobin,
        LeastConnections,
        WeightedLeastConnections,
        Random,
        WeightedRandom,
        PowerOfTwo,
        LeastResponseTime,
        IPHash,
        ConsistentHash,
        Maglev,
    )
}


def new(name: str) -> Balancer:
    return REGISTRY[name]()
