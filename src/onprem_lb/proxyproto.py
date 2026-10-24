"""PROXY protocol v1/v2 headers (haproxy spec), so targets see client addresses."""

from __future__ import annotations

import ipaddress
import struct

V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"


def header(version: str, src: tuple[str, int], dst: tuple[str, int]) -> bytes:
    try:
        s = ipaddress.ip_address(src[0])
        d = ipaddress.ip_address(dst[0])
    except ValueError:
        s = d = None
    if s is not None and d is not None and s.version != d.version:
        # e.g. IPv4 client on a dual-stack socket: map to the client's family
        d = ipaddress.ip_address("0.0.0.0") if s.version == 4 else ipaddress.ip_address("::")
    if version == "v1":
        if s is None:
            return b"PROXY UNKNOWN\r\n"
        fam = "TCP4" if s.version == 4 else "TCP6"
        return f"PROXY {fam} {s} {d} {src[1]} {dst[1]}\r\n".encode()
    if s is None:
        return V2_SIGNATURE + bytes([0x20, 0x00]) + struct.pack("!H", 0)  # LOCAL
    if s.version == 4:
        body = s.packed + d.packed + struct.pack("!HH", src[1], dst[1])
        fam = 0x11  # TCP over IPv4
    else:
        body = s.packed + d.packed + struct.pack("!HH", src[1], dst[1])
        fam = 0x21  # TCP over IPv6
    return V2_SIGNATURE + bytes([0x21, fam]) + struct.pack("!H", len(body)) + body
