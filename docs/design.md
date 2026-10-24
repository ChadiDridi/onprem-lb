# Design notes

These notes are terse and record decisions with their reasons.

## Shape

| Decision | Why |
|---|---|
| AWS ELB resource model (LB → listeners → rules → target groups) | Operators already know it, and it maps cleanly onto a REST API |
| The config is one dict; every change re-validates the whole thing | One code path for the file, SIGHUP and the API. No partially valid states |
| Diff-based apply with rollback | Listeners whose `(lb, bind, port, protocol)` is unchanged keep their sockets (rules and certificates swap in place). Target groups keep health and counters |
| Python asyncio + optional uvloop, with PyYAML as the only dependency | A small, readable, hackable codebase. Throughput is limited, so the README states it |
| `SO_REUSEPORT` worker processes | The way past the GIL. The kernel spreads connections, and UDP flows hash by 4-tuple so client affinity holds |
| Master owns config; workers apply all-or-nothing over JSON-line control sockets | Atomic multi-process changes, plus crash respawn |

## Data plane

- **TCP/TLS:** pick a target, connect, and retry up to 3 different targets on connect failure. After that, a bidirectional splice with half-close propagation (plain TCP) and a shared idle timer.
- **UDP:** one session per client address, with a connected datagram socket to the chosen target. Datagrams that arrive while the target is being picked are buffered (up to 64). Sessions are swept after the idle timeout.
- **HTTP:** a strict HTTP/1.1 parser.
  - Rejected: TE+CL together, conflicting CL, obs-fold, whitespace before the colon, and non-strict-hex chunk sizes (Python's `int(x, 16)` accepts `0x10`, `+1` and `1_0`).
  - Request bodies stream to the target. Chunked bodies are forwarded verbatim after validation.
  - Close-delimited responses are re-chunked for HTTP/1.1 clients.
  - `Expect: 100-continue` is answered by the LB.
  - Upgrades (WebSocket) become a raw tunnel.
- **Retries:** HTTP retries happen only when nothing was sent yet (connect failures), or on a stale pooled keep-alive connection for requests without a body. Once the response head has gone to the client, failures close the connection instead of writing a bogus 502.
- **TLS:** a front `SSLContext` with an `sni_callback` that assigns per-certificate contexts, so certificates can be swapped without rebinding.

## Algorithms

- All algorithms choose among *routable* targets: healthy, not draining, weight > 0, not passively ejected.
- Hashes use blake2b, which is stable across processes and restarts. Python's `hash()` is randomized.
- **Consistent hash:** a ring with 160 virtual nodes per weight unit. Removing a target moves only its own keys (tested).
- **Maglev:** follows Eisenbud et al. (NSDI 2016).
  - The table size is a prime of at least 100×N, capped at 100003, to keep rebuilds short in pure Python.
  - Weights scale how many fill turns each target gets.
  - Both properties are tested: imbalance under 15%, and under 3% extra disruption when a target is removed.
- **Smooth weighted round robin:** the nginx algorithm. The test checks nginx's documented 5/1/1 sequence.
- **Least response time:** EWMA (α = 0.3) of time to response headers, scaled by `(active + 1) / weight`.

## Health

- Active checks per target group:
  - `initial` → `healthy` after 1 success.
  - `healthy` → `unhealthy` after `unhealthy_threshold` consecutive failures.
  - `unhealthy` → `healthy` after `healthy_threshold` successes.
- Passive: 3 consecutive connect failures eject the target for 10 s.
- Deregistered targets drain. They take no new connections and keep existing ones until `deregistration_delay`, after which the connections are reset.

## Not done

- HTTP/2, mTLS client auth, rate limiting, caching, compression.
- Cross-node HA (VRRP/BGP).
- Shared health state across workers.
