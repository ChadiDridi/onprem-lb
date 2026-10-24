import random
from collections import Counter
from dataclasses import dataclass

from onprem_lb import algorithms
from onprem_lb.algorithms import PickContext


@dataclass(eq=False)
class C:
    address: str
    weight: int = 1
    active: int = 0
    ewma: float = 0.0


def picks(bal, cands, n, ctx=None):
    return [bal.pick(cands, ctx or PickContext()).address for _ in range(n)]


def test_round_robin_cycles():
    cs = [C("a"), C("b"), C("c")]
    assert picks(algorithms.RoundRobin(), cs, 6) == ["a", "b", "c", "a", "b", "c"]


def test_smooth_weighted_round_robin_matches_nginx():
    cs = [C("a", 5), C("b", 1), C("c", 1)]
    # nginx's documented sequence for weights 5,1,1.
    assert picks(algorithms.WeightedRoundRobin(), cs, 7) == ["a", "a", "b", "a", "c", "a", "a"]


def test_least_connections_and_weighted():
    cs = [C("a", active=5), C("b", active=1), C("c", active=3)]
    assert algorithms.LeastConnections().pick(cs, PickContext()).address == "b"
    cs = [C("a", weight=10, active=5), C("b", weight=1, active=1)]
    assert algorithms.WeightedLeastConnections().pick(cs, PickContext()).address == "a"  # 0.5 < 1.0


def test_least_connections_rotates_ties():
    cs = [C("a"), C("b"), C("c")]
    assert set(picks(algorithms.LeastConnections(), cs, 3)) == {"a", "b", "c"}


def test_power_of_two_prefers_less_loaded():
    cs = [C("busy", active=100), C("idle", active=0)]
    b = algorithms.PowerOfTwo(random.Random(1))
    got = Counter(picks(b, cs, 1000))
    # Busy only wins when both samples land on it (~25%).
    assert got["idle"] > 650


def test_weighted_random_respects_weights():
    cs = [C("a", 3), C("b", 1)]
    got = Counter(picks(algorithms.WeightedRandom(random.Random(7)), cs, 4000))
    assert 0.70 < got["a"] / 4000 < 0.80


def test_least_response_time():
    cs = [C("slow", ewma=0.2), C("fast", ewma=0.01), C("fast-busy", ewma=0.01, active=50)]
    assert algorithms.LeastResponseTime().pick(cs, PickContext()).address == "fast"


def keys(n):
    return [PickContext(key=f"user-{i}") for i in range(n)]


def placement(bal, cs, ctxs):
    return {c.key: bal.pick(cs, c).address for c in ctxs}


def test_hashes_are_deterministic_across_instances():
    cs = [C(f"10.0.0.{i}:80") for i in range(5)]
    for cls in (algorithms.IPHash, algorithms.ConsistentHash, algorithms.Maglev):
        assert placement(cls(), cs, keys(200)) == placement(cls(), cs, keys(200))


def test_consistent_hash_minimal_disruption():
    cs = [C(f"10.0.0.{i}:80") for i in range(10)]
    ctxs = keys(5000)
    before = placement(algorithms.ConsistentHash(), cs, ctxs)
    removed = cs[3].address
    after = placement(algorithms.ConsistentHash(), [c for c in cs if c.address != removed], ctxs)
    moved = [k for k in before if before[k] != after[k]]
    # Only keys that lived on the removed target move.
    assert all(before[k] == removed for k in moved)
    assert len(moved) == sum(1 for v in before.values() if v == removed)


def test_maglev_balance_and_disruption():
    cs = [C(f"10.0.0.{i}:80") for i in range(10)]
    ctxs = keys(20000)
    before = placement(algorithms.Maglev(), cs, ctxs)
    counts = Counter(before.values())
    assert max(counts.values()) / min(counts.values()) < 1.15  # near-even
    removed = cs[0].address
    after = placement(algorithms.Maglev(), cs[1:], ctxs)
    moved_other = sum(1 for k in before if before[k] != removed and before[k] != after[k])
    assert moved_other / len(ctxs) < 0.03  # paper: small extra disruption


def test_maglev_weights():
    cs = [C("a", 2), C("b", 1)]
    got = Counter(placement(algorithms.Maglev(), cs, keys(30000)).values())
    assert 0.62 < got["a"] / 30000 < 0.71


def test_consistent_hash_weights():
    cs = [C("a", 3), C("b", 1)]
    got = Counter(placement(algorithms.ConsistentHash(), cs, keys(20000)).values())
    assert 0.70 < got["a"] / 20000 < 0.80


def test_empty_candidates():
    for name in algorithms.REGISTRY:
        assert algorithms.new(name).pick([], PickContext()) is None
