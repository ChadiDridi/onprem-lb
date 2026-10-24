"""Minimal Prometheus metrics (text exposition format 0.0.4)."""

from __future__ import annotations

import bisect
import threading
from collections import defaultdict

_LOCK = threading.Lock()


def _labels(names: tuple[str, ...], values: tuple[str, ...], extra: str = "") -> str:
    parts = [f'{n}="{_esc(v)}"' for n, v in zip(names, values)]
    if extra:
        parts.append(extra)
    return "{" + ",".join(parts) + "}" if parts else ""


def _esc(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


class _Metric:
    kind = ""

    def __init__(self, name: str, help: str, labels: tuple[str, ...] = ()):
        self.name, self.help, self.label_names = name, help, labels

    def header(self) -> list[str]:
        return [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} {self.kind}"]


class Counter(_Metric):
    kind = "counter"

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.values: dict[tuple[str, ...], float] = defaultdict(float)

    def inc(self, *labels: str, by: float = 1.0) -> None:
        self.values[labels] += by

    def render(self) -> list[str]:
        return self.header() + [f"{self.name}{_labels(self.label_names, k)} {v:g}" for k, v in sorted(self.values.items())]


class Gauge(Counter):
    kind = "gauge"

    def set(self, *labels: str, value: float) -> None:
        self.values[labels] = value

    def remove(self, *labels: str) -> None:
        self.values.pop(labels, None)


class Histogram(_Metric):
    kind = "histogram"
    BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30)

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.counts: dict[tuple[str, ...], list[int]] = {}
        self.sums: dict[tuple[str, ...], float] = defaultdict(float)

    def observe(self, value: float, *labels: str) -> None:
        c = self.counts.get(labels)
        if c is None:
            c = self.counts[labels] = [0] * (len(self.BUCKETS) + 1)
        c[bisect.bisect_left(self.BUCKETS, value)] += 1
        self.sums[labels] += value

    def render(self) -> list[str]:
        out = self.header()
        for k, c in sorted(self.counts.items()):
            acc = 0
            for b, n in zip(self.BUCKETS, c):
                acc += n
                le = 'le="%g"' % b
                out.append(f"{self.name}_bucket{_labels(self.label_names, k, le)} {acc}")
            acc += c[-1]
            le = 'le="+Inf"'
            out.append(f"{self.name}_bucket{_labels(self.label_names, k, le)} {acc}")
            out.append(f"{self.name}_sum{_labels(self.label_names, k)} {self.sums[k]:g}")
            out.append(f"{self.name}_count{_labels(self.label_names, k)} {acc}")
        return out


class Registry:
    def __init__(self) -> None:
        self.connections = Counter("onprem_lb_connections_total", "Accepted client connections.", ("lb", "listener"))
        self.active = Gauge("onprem_lb_active_connections", "Open client connections.", ("lb", "listener"))
        self.rejected = Counter("onprem_lb_rejected_connections_total", "Connections refused (max_connections).", ("lb", "listener"))
        self.bytes = Counter("onprem_lb_bytes_total", "Bytes proxied.", ("lb", "listener", "direction"))
        self.requests = Counter("onprem_lb_http_requests_total", "HTTP requests by response code class.", ("lb", "listener", "target_group", "code"))
        self.duration = Histogram("onprem_lb_http_request_duration_seconds", "Time to upstream response headers.", ("lb", "listener", "target_group"))
        self.upstream_errors = Counter("onprem_lb_upstream_errors_total", "Upstream failures.", ("target_group", "kind"))
        self.target_healthy = Gauge("onprem_lb_target_healthy", "1 if the target is routable.", ("target_group", "target"))
        self.target_active = Gauge("onprem_lb_target_active", "Active connections/requests per target.", ("target_group", "target"))
        self.udp_sessions = Gauge("onprem_lb_udp_sessions", "Live UDP sessions.", ("lb", "listener"))
        self.config_reloads = Counter("onprem_lb_config_applies_total", "Config applies by result.", ("result",))

    # Max-merged gauges (a per-target fact, not a per-worker quantity).
    MAX_MERGED = {"target_healthy"}

    def dump(self) -> dict:
        """Structured values, for merging metrics across worker processes."""
        out: dict = {}
        for attr, m in vars(self).items():
            if isinstance(m, Histogram):
                out[attr] = {"counts": [[list(k), v] for k, v in m.counts.items()], "sums": [[list(k), v] for k, v in m.sums.items()]}
            elif isinstance(m, Counter):
                out[attr] = {"values": [[list(k), v] for k, v in m.values.items()]}
        return out

    @classmethod
    def merged(cls, dumps: list[dict]) -> Registry:
        r = cls()
        for d in dumps:
            for attr, data in d.items():
                m = getattr(r, attr, None)
                if isinstance(m, Histogram):
                    for k, counts in data["counts"]:
                        cur = m.counts.setdefault(tuple(k), [0] * len(counts))
                        m.counts[tuple(k)] = [a + b for a, b in zip(cur, counts)]
                    for k, v in data["sums"]:
                        m.sums[tuple(k)] += v
                elif isinstance(m, Counter):
                    for k, v in data["values"]:
                        k = tuple(k)
                        m.values[k] = max(m.values.get(k, 0), v) if attr in cls.MAX_MERGED else m.values[k] + v
        return r

    def render(self) -> str:
        with _LOCK:
            lines: list[str] = []
            for m in vars(self).values():
                if isinstance(m, _Metric):
                    lines.extend(m.render())
            return "\n".join(lines) + "\n"
