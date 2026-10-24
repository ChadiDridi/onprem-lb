"""Configuration model and validation.

The canonical config is a plain dict (what YAML and the admin API speak).
``parse`` validates it into frozen dataclasses; the runtime keeps both, so API
edits are applied to the dict and re-validated as a whole before going live.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

NETWORK = "network"
APPLICATION = "application"

NETWORK_PROTOCOLS = {"tcp", "udp", "tls"}
APPLICATION_PROTOCOLS = {"http", "https"}

ALGORITHMS = {
    "round_robin",
    "weighted_round_robin",
    "least_connections",
    "weighted_least_connections",
    "random",
    "weighted_random",
    "power_of_two",
    "ip_hash",
    "consistent_hash",
    "maglev",
    "least_response_time",
}
HASH_ALGORITHMS = {"ip_hash", "consistent_hash", "maglev"}


class ConfigError(ValueError):
    """Invalid configuration. The message starts with the offending path."""


@dataclass(frozen=True)
class Target:
    host: str
    port: int
    weight: int = 1

    @property
    def address(self) -> str:
        return f"[{self.host}]:{self.port}" if ":" in self.host else f"{self.host}:{self.port}"


@dataclass(frozen=True)
class HealthCheck:
    protocol: str = "tcp"  # tcp | http | https | none
    path: str = "/"
    port: int | None = None  # default: the target's port
    interval: float = 5.0
    timeout: float = 2.0
    healthy_threshold: int = 2
    unhealthy_threshold: int = 3
    matcher: tuple[tuple[int, int], ...] = ((200, 399),)
    host: str | None = None  # Host header for http checks


@dataclass(frozen=True)
class Stickiness:
    enabled: bool = False
    cookie: str = "onprem_lb"
    duration: int = 86400


@dataclass(frozen=True)
class TargetGroup:
    name: str
    protocol: str  # tcp | udp | http
    algorithm: str = "round_robin"
    hash_key: str = "source_ip"
    targets: tuple[Target, ...] = ()
    health_check: HealthCheck = field(default_factory=HealthCheck)
    stickiness: Stickiness = field(default_factory=Stickiness)
    deregistration_delay: float = 30.0
    proxy_protocol: str = "none"  # none | v1 | v2 (tcp target groups)
    tls: bool = False  # connect to targets over TLS (http target groups)
    tls_verify: bool = True


@dataclass(frozen=True)
class WeightedGroup:
    target_group: str
    weight: int = 1


@dataclass(frozen=True)
class Action:
    type: str  # forward | redirect | fixed_response
    forward: tuple[WeightedGroup, ...] = ()
    status: int = 0
    location: str = ""
    body: str = ""
    content_type: str = "text/plain"
    headers: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Conditions:
    host: tuple[str, ...] = ()
    path: tuple[str, ...] = ()
    method: tuple[str, ...] = ()
    header: tuple[tuple[str, tuple[str, ...]], ...] = ()
    query: tuple[tuple[str, tuple[str, ...]], ...] = ()
    source_ip: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()


@dataclass(frozen=True)
class Rule:
    priority: int
    conditions: Conditions
    action: Action


@dataclass(frozen=True)
class Certificate:
    cert: str
    key: str
    server_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class Timeouts:
    connect: float = 5.0
    idle: float = 60.0
    response: float = 60.0  # application: time to response headers
    client_header: float = 30.0  # application: time to read request headers


@dataclass(frozen=True)
class Listener:
    port: int
    protocol: str
    bind: str = "0.0.0.0"
    default_action: Action | None = None
    rules: tuple[Rule, ...] = ()
    certificates: tuple[Certificate, ...] = ()
    timeouts: Timeouts = field(default_factory=Timeouts)
    max_connections: int = 10000


@dataclass(frozen=True)
class LoadBalancer:
    name: str
    type: str
    listeners: tuple[Listener, ...]


@dataclass(frozen=True)
class Admin:
    listen_host: str = "127.0.0.1"
    listen_port: int = 9900
    token_env: str = "ONPREM_LB_ADMIN_TOKEN"


@dataclass(frozen=True)
class Config:
    load_balancers: dict[str, LoadBalancer]
    target_groups: dict[str, TargetGroup]
    admin: Admin


# --------------------------------------------------------------------------
# parsing helpers


def _err(path: str, msg: str) -> ConfigError:
    return ConfigError(f"{path}: {msg}")


def _map(v: Any, path: str) -> dict:
    if v is None:
        return {}
    if not isinstance(v, dict):
        raise _err(path, "must be a mapping")
    return v


def _list(v: Any, path: str) -> list:
    if v is None:
        return []
    if isinstance(v, (str, int)):
        return [v]
    if not isinstance(v, list):
        raise _err(path, "must be a list")
    return v


def _known(d: dict, allowed: set[str], path: str) -> None:
    extra = sorted(set(d) - allowed)
    if extra:
        raise _err(path, f"unknown field(s): {', '.join(map(str, extra))}")


def _int(v: Any, path: str, lo: int, hi: int) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        raise _err(path, "must be an integer")
    if not lo <= v <= hi:
        raise _err(path, f"must be between {lo} and {hi}")
    return v


def _num(v: Any, path: str, lo: float = 0.0) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise _err(path, "must be a number (seconds)")
    if v < lo:
        raise _err(path, f"must be >= {lo}")
    return float(v)


def _str(v: Any, path: str) -> str:
    if not isinstance(v, str) or not v:
        raise _err(path, "must be a non-empty string")
    return v


def _choice(v: Any, path: str, choices: set[str]) -> str:
    if v not in choices:
        raise _err(path, f"must be one of {', '.join(sorted(map(str, choices)))}")
    return v


def parse_address(v: Any, path: str) -> tuple[str, int]:
    """Parse "host:port" or "[v6]:port"."""
    s = _str(v, path)
    if s.startswith("["):
        host, sep, port = s[1:].partition("]:")
    else:
        host, sep, port = s.rpartition(":")
    if not sep or not host or not port.isdigit():
        raise _err(path, f"{s!r} is not host:port")
    return host, _int(int(port), path, 1, 65535)


def _matcher(v: Any, path: str) -> tuple[tuple[int, int], ...]:
    out = []
    for part in str(v).split(","):
        part = part.strip()
        lo, _, hi = part.partition("-")
        if not lo.isdigit() or (hi and not hi.isdigit()):
            raise _err(path, f"bad status matcher {part!r} (use 200 or 200-399, comma-separated)")
        out.append((int(lo), int(hi or lo)))
    return tuple(out)


# --------------------------------------------------------------------------
# sections


def _target_group(name: str, d: dict, path: str) -> TargetGroup:
    _known(
        d,
        {
            "protocol",
            "algorithm",
            "hash_key",
            "targets",
            "health_check",
            "stickiness",
            "deregistration_delay",
            "proxy_protocol",
            "tls",
            "tls_verify",
        },
        path,
    )
    protocol = _choice(d.get("protocol", "http"), f"{path}.protocol", {"tcp", "udp", "http"})
    algorithm = _choice(d.get("algorithm", "round_robin"), f"{path}.algorithm", ALGORITHMS)
    hash_key = d.get("hash_key", "source_ip")
    _hash_key(hash_key, protocol, f"{path}.hash_key")

    targets = []
    seen = set()
    for i, t in enumerate(_list(d.get("targets"), f"{path}.targets")):
        tp = f"{path}.targets[{i}]"
        if isinstance(t, str):
            t = {"address": t}
        t = _map(t, tp)
        _known(t, {"address", "weight"}, tp)
        host, port = parse_address(t.get("address"), f"{tp}.address")
        weight = _int(t.get("weight", 1), f"{tp}.weight", 0, 1000)
        tgt = Target(host, port, weight)
        if tgt.address in seen:
            raise _err(tp, f"duplicate target {tgt.address}")
        seen.add(tgt.address)
        targets.append(tgt)

    hp = f"{path}.health_check"
    h = _map(d.get("health_check"), hp)
    _known(h, {"protocol", "path", "port", "interval", "timeout", "healthy_threshold", "unhealthy_threshold", "matcher", "host"}, hp)
    hc_default = "http" if protocol == "http" else ("tcp" if protocol == "tcp" else "none")
    hc = HealthCheck(
        protocol=_choice(h.get("protocol", hc_default), f"{hp}.protocol", {"tcp", "http", "https", "none"}),
        path=_str(h.get("path", "/"), f"{hp}.path"),
        port=_int(h["port"], f"{hp}.port", 1, 65535) if "port" in h else None,
        interval=(interval := _num(h.get("interval", 5), f"{hp}.interval", 0.1)),
        timeout=_num(h.get("timeout", min(2.0, interval / 2)), f"{hp}.timeout", 0.05),
        healthy_threshold=_int(h.get("healthy_threshold", 2), f"{hp}.healthy_threshold", 1, 100),
        unhealthy_threshold=_int(h.get("unhealthy_threshold", 3), f"{hp}.unhealthy_threshold", 1, 100),
        matcher=_matcher(h.get("matcher", "200-399"), f"{hp}.matcher"),
        host=h.get("host"),
    )
    if hc.timeout >= hc.interval:
        raise _err(f"{hp}.timeout", "must be less than interval")
    if protocol == "udp" and hc.protocol != "none" and hc.port is None:
        raise _err(f"{hp}.port", "udp target groups need a TCP/HTTP health check port (or protocol: none)")

    sp = f"{path}.stickiness"
    s = _map(d.get("stickiness"), sp)
    _known(s, {"enabled", "cookie", "duration"}, sp)
    stick = Stickiness(
        enabled=bool(s.get("enabled", False)),
        cookie=_str(s.get("cookie", "onprem_lb"), f"{sp}.cookie"),
        duration=_int(s.get("duration", 86400), f"{sp}.duration", 1, 7 * 86400),
    )
    if stick.enabled and protocol != "http":
        raise _err(sp, "cookie stickiness needs an http target group; use a hash algorithm with hash_key: source_ip for tcp/udp")

    pp = _choice(d.get("proxy_protocol", "none"), f"{path}.proxy_protocol", {"none", "v1", "v2"})
    if pp != "none" and protocol != "tcp":
        raise _err(f"{path}.proxy_protocol", "only supported for tcp target groups")

    return TargetGroup(
        name=name,
        protocol=protocol,
        algorithm=algorithm,
        hash_key=hash_key,
        targets=tuple(targets),
        health_check=hc,
        stickiness=stick,
        deregistration_delay=_num(d.get("deregistration_delay", 30), f"{path}.deregistration_delay"),
        proxy_protocol=pp,
        tls=bool(d.get("tls", False)),
        tls_verify=bool(d.get("tls_verify", True)),
    )


def _hash_key(v: Any, protocol: str, path: str) -> None:
    s = _str(v, path)
    if s in ("source_ip", "source_ip_port"):
        return
    if protocol != "http":
        raise _err(path, "tcp/udp target groups can hash on source_ip or source_ip_port only")
    if s in ("uri", "path", "host"):
        return
    kind, _, name = s.partition(":")
    if kind in ("header", "cookie", "query") and name:
        return
    raise _err(path, "must be source_ip, source_ip_port, uri, path, host, header:NAME, cookie:NAME or query:NAME")


def _action(v: Any, path: str, groups: dict[str, TargetGroup], lb_type: str) -> Action:
    d = _map(v, path)
    kinds = [k for k in ("forward", "redirect", "fixed_response") if k in d]
    if len(kinds) != 1 or len(d) != 1:
        raise _err(path, "needs exactly one of forward, redirect, fixed_response")
    kind = kinds[0]
    if kind != "forward" and lb_type == NETWORK:
        raise _err(path, "network load balancers only support forward")
    if kind == "forward":
        fwd = d["forward"]
        items = [{"target_group": fwd}] if isinstance(fwd, str) else _list(fwd, f"{path}.forward")
        out = []
        for i, it in enumerate(items):
            ip = f"{path}.forward[{i}]"
            if isinstance(it, str):
                it = {"target_group": it}
            it = _map(it, ip)
            _known(it, {"target_group", "weight"}, ip)
            tg = _str(it.get("target_group"), f"{ip}.target_group")
            if tg not in groups:
                raise _err(f"{ip}.target_group", f"unknown target group {tg!r}")
            out.append(WeightedGroup(tg, _int(it.get("weight", 1), f"{ip}.weight", 0, 1000)))
        if not out or sum(w.weight for w in out) == 0:
            raise _err(f"{path}.forward", "needs at least one target group with weight > 0")
        if lb_type == NETWORK and len(out) > 1:
            raise _err(f"{path}.forward", "network load balancers forward to a single target group")
        return Action(type="forward", forward=tuple(out))
    if kind == "redirect":
        r = _map(d["redirect"], f"{path}.redirect")
        _known(r, {"status", "location"}, f"{path}.redirect")
        return Action(
            type="redirect",
            status=_choice(r.get("status", 301), f"{path}.redirect.status", {301, 302, 303, 307, 308}),
            location=_str(r.get("location"), f"{path}.redirect.location"),
        )
    f = _map(d["fixed_response"], f"{path}.fixed_response")
    _known(f, {"status", "body", "content_type", "headers"}, f"{path}.fixed_response")
    hdrs = _map(f.get("headers"), f"{path}.fixed_response.headers")
    return Action(
        type="fixed_response",
        status=_int(f.get("status", 200), f"{path}.fixed_response.status", 100, 599),
        body=str(f.get("body", "")),
        content_type=str(f.get("content_type", "text/plain")),
        headers=tuple((str(k), str(v)) for k, v in hdrs.items()),
    )


def _patterns(v: Any, path: str) -> tuple[str, ...]:
    return tuple(_str(p, f"{path}[{i}]") for i, p in enumerate(_list(v, path)))


def _conditions(v: Any, path: str) -> Conditions:
    d = _map(v, path)
    _known(d, {"host", "path", "method", "header", "query", "source_ip"}, path)

    def kv(name: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
        m = _map(d.get(name), f"{path}.{name}")
        return tuple((str(k), _patterns(vals, f"{path}.{name}.{k}")) for k, vals in m.items())

    nets = []
    for i, c in enumerate(_list(d.get("source_ip"), f"{path}.source_ip")):
        try:
            nets.append(ipaddress.ip_network(str(c), strict=False))
        except ValueError as e:
            raise _err(f"{path}.source_ip[{i}]", str(e)) from None
    return Conditions(
        host=tuple(h.lower() for h in _patterns(d.get("host"), f"{path}.host")),
        path=_patterns(d.get("path"), f"{path}.path"),
        method=tuple(m.upper() for m in _patterns(d.get("method"), f"{path}.method")),
        header=tuple((k.lower(), v) for k, v in kv("header")),
        query=kv("query"),
        source_ip=tuple(nets),
    )


def _listener(d: dict, path: str, lb_type: str, groups: dict[str, TargetGroup]) -> Listener:
    _known(d, {"port", "protocol", "bind", "default_action", "rules", "certificates", "timeouts", "max_connections"}, path)
    allowed = NETWORK_PROTOCOLS if lb_type == NETWORK else APPLICATION_PROTOCOLS
    protocol = _choice(d.get("protocol"), f"{path}.protocol", allowed)
    port = _int(d.get("port"), f"{path}.port", 1, 65535)
    bind = _str(d.get("bind", "0.0.0.0"), f"{path}.bind")

    if "default_action" not in d:
        raise _err(f"{path}.default_action", "is required")
    default = _action(d["default_action"], f"{path}.default_action", groups, lb_type)

    rules = []
    rule_list = _list(d.get("rules"), f"{path}.rules")
    if rule_list and lb_type == NETWORK:
        raise _err(f"{path}.rules", "rules are for application load balancers")
    prios = set()
    for i, r in enumerate(rule_list):
        rp = f"{path}.rules[{i}]"
        r = _map(r, rp)
        _known(r, {"priority", "conditions", "action"}, rp)
        prio = _int(r.get("priority"), f"{rp}.priority", 1, 50000)
        if prio in prios:
            raise _err(f"{rp}.priority", f"duplicate priority {prio}")
        prios.add(prio)
        rules.append(Rule(prio, _conditions(r.get("conditions"), f"{rp}.conditions"), _action(r.get("action"), f"{rp}.action", groups, lb_type)))
    rules.sort(key=lambda r: r.priority)

    certs = []
    for i, c in enumerate(_list(d.get("certificates"), f"{path}.certificates")):
        cp = f"{path}.certificates[{i}]"
        c = _map(c, cp)
        _known(c, {"cert", "key", "server_names"}, cp)
        certs.append(
            Certificate(
                _str(c.get("cert"), f"{cp}.cert"),
                _str(c.get("key"), f"{cp}.key"),
                tuple(s.lower() for s in _patterns(c.get("server_names"), f"{cp}.server_names")),
            )
        )
    tls = protocol in ("tls", "https")
    if tls and not certs:
        raise _err(f"{path}.certificates", f"{protocol} listeners need at least one certificate")
    if certs and not tls:
        raise _err(f"{path}.certificates", f"{protocol} listeners do not terminate TLS")

    tp = f"{path}.timeouts"
    t = _map(d.get("timeouts"), tp)
    _known(t, {"connect", "idle", "response", "client_header"}, tp)
    idle_default = 120.0 if protocol == "udp" else 60.0
    timeouts = Timeouts(
        connect=_num(t.get("connect", 5), f"{tp}.connect", 0.05),
        idle=_num(t.get("idle", idle_default), f"{tp}.idle", 0.05),
        response=_num(t.get("response", 60), f"{tp}.response", 0.05),
        client_header=_num(t.get("client_header", 30), f"{tp}.client_header", 0.05),
    )

    # Target group protocol must match what the listener speaks.
    want = {"tcp": "tcp", "tls": "tcp", "udp": "udp", "http": "http", "https": "http"}[protocol]
    for a in [default] + [r.action for r in rules]:
        for wg in a.forward:
            got = groups[wg.target_group].protocol
            if got != want:
                raise _err(path, f"{protocol} listener forwards to {got} target group {wg.target_group!r}; needs a {want} target group")

    return Listener(
        port=port,
        protocol=protocol,
        bind=bind,
        default_action=default,
        rules=tuple(rules),
        certificates=tuple(certs),
        timeouts=timeouts,
        max_connections=_int(d.get("max_connections", 10000), f"{path}.max_connections", 1, 1_000_000),
    )


def parse(raw: Any) -> Config:
    """Validate a raw config dict. Raises ConfigError."""
    d = _map(raw, "config")
    _known(d, {"admin", "target_groups", "load_balancers"}, "config")

    a = _map(d.get("admin"), "admin")
    _known(a, {"listen", "token_env"}, "admin")
    ahost, aport = parse_address(a.get("listen", "127.0.0.1:9900"), "admin.listen")
    admin = Admin(ahost, aport, _str(a.get("token_env", "ONPREM_LB_ADMIN_TOKEN"), "admin.token_env"))

    groups = {}
    for name, g in _map(d.get("target_groups"), "target_groups").items():
        groups[str(name)] = _target_group(str(name), _map(g, f"target_groups.{name}"), f"target_groups.{name}")

    lbs = {}
    bound: dict[tuple[str, int, str], str] = {}
    for name, lb in _map(d.get("load_balancers"), "load_balancers").items():
        path = f"load_balancers.{name}"
        lb = _map(lb, path)
        _known(lb, {"type", "listeners"}, path)
        lb_type = _choice(lb.get("type"), f"{path}.type", {NETWORK, APPLICATION})
        listeners = []
        for i, ld in enumerate(_list(lb.get("listeners"), f"{path}.listeners")):
            lp = f"{path}.listeners[{i}]"
            listener = _listener(_map(ld, lp), lp, lb_type, groups)
            transport = "udp" if listener.protocol == "udp" else "tcp"
            key = (listener.bind, listener.port, transport)
            if key in bound:
                raise _err(lp, f"{transport} {listener.bind}:{listener.port} already used by {bound[key]}")
            bound[key] = lp
            listeners.append(listener)
        if not listeners:
            raise _err(f"{path}.listeners", "needs at least one listener")
        lbs[str(name)] = LoadBalancer(str(name), lb_type, tuple(listeners))

    if (admin.listen_host, admin.listen_port, "tcp") in bound:
        raise _err("admin.listen", "collides with a listener")
    return Config(load_balancers=lbs, target_groups=groups, admin=admin)
