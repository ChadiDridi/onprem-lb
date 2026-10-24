"""ALB rule matching and action helpers."""

from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass
from fnmatch import fnmatchcase

from .. import config
from .parser import Request


@dataclass
class RequestView:
    req: Request
    host: str  # lowercased, without port
    client_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    scheme: str
    port: int


def host_of(req: Request) -> str:
    h = (req.headers.get("host") or "").strip().lower()
    if h.startswith("["):  # [v6]:port
        return h[: h.find("]") + 1] if "]" in h else h
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


def matches(c: config.Conditions, v: RequestView) -> bool:
    if c.host and not any(fnmatchcase(v.host, p) for p in c.host):
        return False
    if c.path and not any(fnmatchcase(v.req.path, p) for p in c.path):
        return False
    if c.method and v.req.method not in c.method:
        return False
    for name, patterns in c.header:
        values = [x.lower() for x in v.req.headers.get_all(name)]
        if not any(fnmatchcase(x, p.lower()) for x in values for p in patterns):
            return False
    if c.query:
        q = v.req.query()
        for name, patterns in c.query:
            if not any(fnmatchcase(x, p) for x in q.get(name, []) for p in patterns):
                return False
    if c.source_ip:
        if v.client_ip is None or not any(v.client_ip in net for net in c.source_ip):
            return False
    return True


def select(listener: config.Listener, v: RequestView) -> config.Action:
    for r in listener.rules:
        if matches(r.conditions, v):
            return r.action
    return listener.default_action


_rng = random.Random()


def pick_group(action: config.Action, rng: random.Random = _rng) -> str:
    groups = [w for w in action.forward if w.weight > 0]
    if len(groups) == 1:
        return groups[0].target_group
    return rng.choices(groups, weights=[g.weight for g in groups])[0].target_group


def redirect_location(template: str, v: RequestView) -> str:
    """Expand {scheme} {host} {port} {path} {query} in a redirect target."""
    out = template
    for k, val in (
        ("{scheme}", v.scheme),
        ("{host}", v.host),
        ("{port}", str(v.port)),
        ("{path}", v.req.path),
        ("{query}", v.req.query_string),
    ):
        out = out.replace(k, val)
    return out


def hash_key(spec: config.TargetGroup, v: RequestView, client_port: int) -> str:
    k = spec.hash_key
    ip = str(v.client_ip) if v.client_ip else ""
    if k == "source_ip":
        return ip
    if k == "source_ip_port":
        return f"{ip}:{client_port}"
    if k == "uri":
        return v.req.target
    if k == "path":
        return v.req.path
    if k == "host":
        return v.host
    kind, _, name = k.partition(":")
    if kind == "header":
        return v.req.headers.get(name) or ip
    if kind == "query":
        vals = v.req.query().get(name)
        return vals[0] if vals else ip
    if kind == "cookie":
        return cookie(v.req, name) or ip
    return ip


def cookie(req: Request, name: str) -> str | None:
    for raw in req.headers.get_all("cookie"):
        for part in raw.split(";"):
            k, sep, val = part.strip().partition("=")
            if sep and k == name:
                return val
    return None
