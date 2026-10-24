"""TLS termination with SNI certificate selection that can be swapped live."""

from __future__ import annotations

import fnmatch
import ssl

from . import config


def _context(cert: config.Certificate, alpn: list[str]) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert.cert, cert.key)
    if alpn:
        ctx.set_alpn_protocols(alpn)
    return ctx


class SNIContexts:
    """A front SSLContext whose sni_callback hands each handshake the context
    for the requested server name (first certificate is the default).
    ``load`` swaps certificates without rebinding the listener."""

    def __init__(self, certs: tuple[config.Certificate, ...], alpn: list[str] | None = None) -> None:
        self.alpn = alpn or []
        self.front = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.front.minimum_version = ssl.TLSVersion.TLSv1_2
        self.front.sni_callback = self._pick
        self._certs: tuple[config.Certificate, ...] = ()
        self.load(certs)

    def load(self, certs: tuple[config.Certificate, ...]) -> None:
        if certs == self._certs:
            return
        built = [(c.server_names, _context(c, self.alpn)) for c in certs]  # raises before swapping
        default = certs[0]
        # The front context also needs a certificate for clients without SNI.
        self.front.load_cert_chain(default.cert, default.key)
        if self.alpn:
            self.front.set_alpn_protocols(self.alpn)
        self._built = built
        self._certs = certs

    def _pick(self, sock: ssl.SSLObject, name: str | None, _ctx: ssl.SSLContext) -> None:
        if name:
            name = name.lower()
            for patterns, ctx in self._built:
                if any(fnmatch.fnmatchcase(name, p) for p in patterns):
                    sock.context = ctx
                    return None
        sock.context = self._built[0][1]
        return None
