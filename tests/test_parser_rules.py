import asyncio
import ipaddress

import pytest

from onprem_lb import proxyproto
from onprem_lb.config import parse
from onprem_lb.http import parser as hp
from onprem_lb.http import rules


def req(raw: bytes) -> hp.Request:
    return hp.parse_request(raw)


@pytest.mark.parametrize(
    "raw,status",
    [
        (b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n", 400),  # CL.TE smuggling
        (b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n", 400),
        (b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n", 400),
        (b"GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n", 501),
        (b"GET / HTTP/1.1\r\nHost : a\r\n\r\n", 400),  # whitespace before colon
        (b"GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n", 400),  # obs-fold
        (b"GET / HTTP/2.0\r\nHost: a\r\n\r\n", 505),
        (b"GET  / HTTP/1.1\r\n\r\n", 400),
    ],
)
def test_rejects_ambiguous_requests(raw, status):
    with pytest.raises(hp.HTTPError) as e:
        r = req(raw.rstrip(b"\r\n"))
        hp.request_framing(r.headers)
    assert e.value.status == status


def test_framing():
    assert hp.request_framing(req(b"POST / HTTP/1.1\r\nContent-Length: 5").headers) == (hp.LENGTH, 5)
    assert hp.request_framing(req(b"POST / HTTP/1.1\r\nContent-Length: 5, 5").headers) == (hp.LENGTH, 5)
    assert hp.request_framing(req(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked").headers) == (hp.CHUNKED, 0)
    assert hp.request_framing(req(b"GET / HTTP/1.1").headers) == (hp.NONE, 0)
    h = hp.Headers()
    assert hp.response_framing("GET", 200, h) == (hp.CLOSE, 0)
    assert hp.response_framing("HEAD", 200, hp.Headers([("Content-Length", "9")])) == (hp.NONE, 0)
    assert hp.response_framing("GET", 304, h) == (hp.NONE, 0)


def copy_chunked(data: bytes):
    async def go():
        r = asyncio.StreamReader()
        r.feed_data(data)
        r.feed_eof()
        out = bytearray()

        class W:
            def write(self, b):
                out.extend(b)

            async def drain(self):
                pass

        await hp.copy_chunked(r, W(), 1)
        return bytes(out)

    return asyncio.run(go())


def test_chunked_passthrough_and_strict_sizes():
    body = b"5;ext=1\r\nhello\r\n0\r\nX-Trailer: y\r\n\r\n"
    assert copy_chunked(body) == body
    for bad in (b"0x5\r\nhello\r\n0\r\n\r\n", b"+5\r\nhello\r\n0\r\n\r\n", b"1_0\r\n", b"5\r\nhelloXX0\r\n\r\n"):
        with pytest.raises(hp.HTTPError):
            copy_chunked(bad)


CFG = parse(
    {
        "target_groups": {"a": {"targets": ["1.1.1.1:80"]}, "b": {"targets": ["1.1.1.2:80"]}},
        "load_balancers": {
            "x": {
                "type": "application",
                "listeners": [
                    {
                        "port": 80,
                        "protocol": "http",
                        "default_action": {"fixed_response": {"status": 404}},
                        "rules": [
                            {"priority": 1, "conditions": {"host": ["api.example.com"], "path": ["/v2/*"]}, "action": {"forward": "b"}},
                            {"priority": 2, "conditions": {"host": ["*.example.com"]}, "action": {"forward": "a"}},
                            {"priority": 3, "conditions": {"header": {"X-Canary": ["yes"]}, "method": ["post"]}, "action": {"forward": "b"}},
                            {"priority": 4, "conditions": {"query": {"beta": ["1"]}, "source_ip": ["192.168.0.0/16"]}, "action": {"forward": "b"}},
                        ],
                    }
                ],
            }
        },
    }
)
LISTENER = CFG.load_balancers["x"].listeners[0]


def view(raw: bytes, ip="10.0.0.1"):
    r = req(raw)
    return rules.RequestView(r, rules.host_of(r), ipaddress.ip_address(ip), "http", 80)


@pytest.mark.parametrize(
    "raw,ip,want",
    [
        (b"GET /v2/users HTTP/1.1\r\nHost: API.example.com:8080", "10.0.0.1", "b"),
        (b"GET /v1/users HTTP/1.1\r\nHost: api.example.com", "10.0.0.1", "a"),
        (b"GET / HTTP/1.1\r\nHost: other.test", "10.0.0.1", "404"),
        (b"POST / HTTP/1.1\r\nHost: other.test\r\nX-Canary: YES", "10.0.0.1", "b"),  # header values case-insensitive
        (b"GET /?beta=1 HTTP/1.1\r\nHost: other.test", "192.168.1.5", "b"),
        (b"GET /?beta=1 HTTP/1.1\r\nHost: other.test", "10.0.0.1", "404"),  # source_ip AND query
    ],
)
def test_rule_matching(raw, ip, want):
    a = rules.select(LISTENER, view(raw, ip))
    got = a.forward[0].target_group if a.type == "forward" else str(a.status)
    assert got == want


def test_redirect_template_and_hash_keys():
    v = view(b"GET /old/x?q=1 HTTP/1.1\r\nHost: shop.test\r\nCookie: a=1; sid=abc\r\nX-User: u7")
    assert rules.redirect_location("https://{host}{path}?{query}", v) == "https://shop.test/old/x?q=1"
    tg = parse({"target_groups": {"t": {"hash_key": "cookie:sid"}}}).target_groups["t"]
    assert rules.hash_key(tg, v, 1234) == "abc"
    tg = parse({"target_groups": {"t": {"hash_key": "header:X-User"}}}).target_groups["t"]
    assert rules.hash_key(tg, v, 1234) == "u7"


def test_proxy_protocol():
    assert proxyproto.header("v1", ("10.0.0.1", 5000), ("10.0.0.2", 443)) == b"PROXY TCP4 10.0.0.1 10.0.0.2 5000 443\r\n"
    assert proxyproto.header("v1", ("::1", 5000), ("::1", 443)) == b"PROXY TCP6 ::1 ::1 5000 443\r\n"
    v2 = proxyproto.header("v2", ("10.0.0.1", 5000), ("10.0.0.2", 443))
    assert v2[:12] == proxyproto.V2_SIGNATURE and v2[12:14] == b"\x21\x11"
    assert v2[14:16] == (12).to_bytes(2, "big")
    assert v2[16:20] == bytes([10, 0, 0, 1]) and v2[24:26] == (5000).to_bytes(2, "big")
