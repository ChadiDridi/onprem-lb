import copy

import pytest

from onprem_lb.config import ConfigError, parse

BASE = {
    "target_groups": {
        "web": {"protocol": "http", "targets": ["10.0.0.1:80", {"address": "10.0.0.2:80", "weight": 3}]},
        "pg": {"protocol": "tcp", "algorithm": "least_connections", "targets": ["10.0.1.1:5432"], "proxy_protocol": "v2"},
        "dns": {"protocol": "udp", "algorithm": "maglev", "targets": ["10.0.2.1:53"], "health_check": {"protocol": "tcp", "port": 53}},
    },
    "load_balancers": {
        "public": {
            "type": "application",
            "listeners": [
                {
                    "port": 8080,
                    "protocol": "http",
                    "default_action": {"forward": "web"},
                    "rules": [
                        {"priority": 20, "conditions": {"path": ["/old/*"]}, "action": {"redirect": {"location": "https://{host}/new"}}},
                        {
                            "priority": 10,
                            "conditions": {"host": ["*.example.com"], "source_ip": ["10.0.0.0/8"]},
                            "action": {"forward": [{"target_group": "web", "weight": 9}, {"target_group": "web", "weight": 1}]},
                        },
                    ],
                }
            ],
        },
        "data": {
            "type": "network",
            "listeners": [
                {"port": 5432, "protocol": "tcp", "default_action": {"forward": "pg"}},
                {"port": 53, "protocol": "udp", "default_action": {"forward": "dns"}},
            ],
        },
    },
}


def test_valid_config():
    cfg = parse(BASE)
    lst = cfg.load_balancers["public"].listeners[0]
    assert [r.priority for r in lst.rules] == [10, 20]  # sorted
    assert cfg.target_groups["web"].targets[1].weight == 3
    assert cfg.target_groups["web"].health_check.protocol == "http"  # default for http groups
    assert cfg.target_groups["dns"].health_check.port == 53
    assert cfg.load_balancers["data"].listeners[1].timeouts.idle == 120  # udp default


def broken(path, value):
    d = copy.deepcopy(BASE)
    node = d
    for k in path[:-1]:
        node = node[k]
    if value is KeyError:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return d


@pytest.mark.parametrize(
    "path,value,msg",
    [
        (["load_balancers", "data", "listeners", 0, "protocol"], "http", "must be one of tcp, tls, udp"),
        (["load_balancers", "public", "listeners", 0, "default_action"], {"forward": "nope"}, "unknown target group 'nope'"),
        (["load_balancers", "public", "listeners", 0, "default_action"], {"forward": "pg"}, "needs a http target group"),
        (["load_balancers", "data", "listeners", 0, "port"], 53, None),  # tcp 53 and udp 53 may coexist
        (["load_balancers", "data", "listeners", 1, "port"], 5432, None),
        (["target_groups", "web", "bogus"], 1, "unknown field(s): bogus"),
        (["target_groups", "pg", "stickiness"], {"enabled": True}, "cookie stickiness needs an http target group"),
        (["target_groups", "pg", "hash_key"], "header:X-User", "can hash on source_ip or source_ip_port only"),
        (["target_groups", "dns", "health_check"], {"protocol": "tcp"}, "need a TCP/HTTP health check port"),
        (["target_groups", "web", "proxy_protocol"], "v1", "only supported for tcp target groups"),
        (["target_groups", "web", "targets"], ["10.0.0.1:80", "10.0.0.1:80"], "duplicate target"),
        (["target_groups", "web", "targets"], ["no-port"], "is not host:port"),
        (["target_groups", "web", "health_check"], {"interval": 1, "timeout": 2}, "must be less than interval"),
        (["target_groups", "web", "algorithm"], "fastest", "must be one of"),
    ],
)
def test_invalid(path, value, msg):
    if msg is None:
        parse(broken(path, value))
        return
    with pytest.raises(ConfigError, match=msg.replace("(", r"\(").replace(")", r"\)")):
        parse(broken(path, value))


def test_duplicate_port_and_priority():
    d = copy.deepcopy(BASE)
    d["load_balancers"]["data"]["listeners"].append(
        {"port": 5432, "protocol": "tls", "default_action": {"forward": "pg"}, "certificates": [{"cert": "c", "key": "k"}]}
    )
    with pytest.raises(ConfigError, match="already used by"):
        parse(d)
    d = copy.deepcopy(BASE)
    d["load_balancers"]["public"]["listeners"][0]["rules"][0]["priority"] = 10
    with pytest.raises(ConfigError, match="duplicate priority 10"):
        parse(d)


def test_network_lb_restrictions():
    d = copy.deepcopy(BASE)
    d["load_balancers"]["data"]["listeners"][0]["default_action"] = {"fixed_response": {"status": 200}}
    with pytest.raises(ConfigError, match="only support forward"):
        parse(d)
    d = copy.deepcopy(BASE)
    d["load_balancers"]["data"]["listeners"][0]["rules"] = [{"priority": 1, "action": {"forward": "pg"}}]
    with pytest.raises(ConfigError, match="rules are for application"):
        parse(d)


def test_tls_listener_needs_certificate():
    d = copy.deepcopy(BASE)
    d["load_balancers"]["data"]["listeners"][0]["protocol"] = "tls"
    with pytest.raises(ConfigError, match="need at least one certificate"):
        parse(d)


def test_admin_cannot_share_listener_port():
    d = copy.deepcopy(BASE)
    d["admin"] = {"listen": "0.0.0.0:8080"}
    with pytest.raises(ConfigError, match="collides"):
        parse(d)


def test_ipv6_target():
    d = copy.deepcopy(BASE)
    d["target_groups"]["web"]["targets"] = ["[::1]:8080"]
    t = parse(d).target_groups["web"].targets[0]
    assert (t.host, t.port, t.address) == ("::1", 8080, "[::1]:8080")


def test_health_check_timeout_defaults_below_interval():
    d = copy.deepcopy(BASE)
    d["target_groups"]["web"]["health_check"] = {"interval": 1}
    assert parse(d).target_groups["web"].health_check.timeout == 0.5
