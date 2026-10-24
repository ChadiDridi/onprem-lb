# onprem-lb

**An on-demand, API-driven load balancer for on-prem and bare metal.** It speaks the AWS ELB model you already know — **network** load balancers (TCP, UDP, TLS) and **application** load balancers (HTTP, HTTPS with host/path/header rules) with **target groups**, **health checks** and **draining** — and lets you create, change and delete all of it at runtime through a REST API, with no restarts.

```sh
# Create a target group and an ALB while the LB is running
curl -X PUT localhost:9900/target-groups/web -H "Authorization: Bearer $TOKEN" -d '{
  "protocol": "http", "algorithm": "least_connections",
  "targets": ["10.0.0.11:8080", "10.0.0.12:8080"], "health_check": {"path": "/healthz"}}'
curl -X PUT localhost:9900/load-balancers/site -H "Authorization: Bearer $TOKEN" -d '{
  "type": "application",
  "listeners": [{"port": 80, "protocol": "http", "default_action": {"forward": "web"}}]}'

# Scale out / in on demand; removed targets drain
curl -X POST   localhost:9900/target-groups/web/targets -H "Authorization: Bearer $TOKEN" -d '{"address": "10.0.0.13:8080"}'
curl -X DELETE localhost:9900/target-groups/web/targets/10.0.0.11:8080 -H "Authorization: Bearer $TOKEN"
```

## Features

| | |
|---|---|
| **Network LB (L4)** | TCP, UDP (per-client sessions), TLS termination with SNI; PROXY protocol v1/v2 so targets see client IPs; half-close; idle timeouts |
| **Application LB (L7)** | HTTP/1.1 and HTTPS (SNI, ALPN); rules on host, path, method, header, query, source IP; actions: forward (weighted across target groups for canaries), redirect, fixed response; WebSocket upgrades; keep-alive upstream pooling; `X-Forwarded-For/Proto/Port`, `X-Request-Id` |
| **Algorithms** | `round_robin`, `weighted_round_robin` (smooth, nginx-style), `least_connections`, `weighted_least_connections`, `random`, `weighted_random`, `power_of_two`, `least_response_time` (EWMA), `ip_hash`, `consistent_hash` (ring), `maglev` |
| **Hash keys** | `source_ip`, `source_ip_port`, and for HTTP: `uri`, `path`, `host`, `header:NAME`, `cookie:NAME`, `query:NAME` |
| **Stickiness** | Cookie stickiness for HTTP; hash-based affinity for TCP/UDP |
| **Health** | Active TCP/HTTP/HTTPS checks with thresholds and status matchers; passive ejection after repeated connect failures; connect retries to other targets |
| **On demand** | REST admin API (create/update/delete LBs, target groups, targets), changes validated as a whole and applied atomically — a bad change is rejected, a failed one rolled back; draining with `deregistration_delay`; config file + `SIGHUP` reload; optional state file so API changes survive restarts |
| **Multi-core** | `--workers N` (or `auto`): worker processes share ports with `SO_REUSEPORT`; config changes reach all workers or none; crashed workers respawn |
| **Ops** | Prometheus `/metrics` (merged across workers), JSON `/state`, access log, graceful shutdown, non-root container |
| **Safety** | Strict HTTP parsing rejects request-smuggling shapes (TE+CL, conflicting lengths, obs-fold, lenient chunk sizes); admin API refuses non-loopback binds without a token |

## Quick start

### Docker Compose demo (two backends, ALB + NLB)

```sh
git clone https://github.com/ChadiDridi/onprem-lb && cd onprem-lb
docker compose -f examples/compose/docker-compose.yaml up --build -d
curl localhost:8080                 # ALB, round robin across whoami-1 / whoami-2
curl localhost:9000                 # NLB, TCP passthrough
curl -H "Authorization: Bearer demo-token" localhost:9900/state
```

Ports busy? `LB_HTTP_PORT=18080 LB_TCP_PORT=19000 LB_ADMIN_PORT=19900 docker compose ... up`.

### Container

```sh
docker run -d --name lb --network host \
  -e ONPREM_LB_ADMIN_TOKEN=change-me \
  -v $PWD/config.yaml:/etc/onprem-lb/config.yaml:ro \
  -v lb-state:/var/lib/onprem-lb \
  ghcr.io/chadidridi/onprem-lb:latest serve -c /etc/onprem-lb/config.yaml \
    --state-file /var/lib/onprem-lb/state.yaml --workers auto
```

`--network host` is the usual choice for a load balancer (no NAT hop, real client IPs). The image runs as uid 10001; binding ports below 1024 works under Docker's default `net.ipv4.ip_unprivileged_port_start=0`, otherwise add `--cap-add NET_BIND_SERVICE`.

### pip

```sh
pip install "onprem-lb[fast] @ git+https://github.com/ChadiDridi/onprem-lb"   # Python 3.11+; [fast] adds uvloop
onprem-lb validate -c examples/config.yaml
onprem-lb serve -c examples/config.yaml --workers auto
```

### GitHub Action

Validate the config on every PR, or run a real load balancer in CI:

```yaml
- uses: ChadiDridi/onprem-lb@v0.1.1
  with:
    config: lb/config.yaml          # validate only (default)

- uses: ChadiDridi/onprem-lb@v0.1.1
  id: lb
  with:
    config: tests/lb.yaml
    mode: serve                     # stays running for the following steps
    workers: "2"
- run: curl localhost:8080 && curl "${{ steps.lb.outputs.admin-url }}/state"
```

Outputs in serve mode: `admin-url`, `pid`, `log`.

## Configuration

A complete annotated example is in [`examples/config.yaml`](examples/config.yaml). The shape:

```yaml
admin:
  listen: 127.0.0.1:9900            # non-loopback requires a token
  token_env: ONPREM_LB_ADMIN_TOKEN  # env var holding the bearer token

target_groups:
  web:
    protocol: http                  # tcp | udp | http (what the targets speak)
    algorithm: least_connections
    hash_key: source_ip             # for ip_hash / consistent_hash / maglev
    targets: [10.0.0.11:8080, {address: 10.0.0.12:8080, weight: 2}]
    health_check: {protocol: http, path: /healthz, interval: 5, timeout: 2,
                   healthy_threshold: 2, unhealthy_threshold: 3, matcher: "200-399"}
    stickiness: {enabled: true, cookie: lb_web, duration: 3600}
    deregistration_delay: 30
    proxy_protocol: none            # v1 | v2 for tcp groups
    tls: false                      # re-encrypt to targets (http groups); tls_verify: true

load_balancers:
  public:
    type: application               # or network
    listeners:
      - port: 443
        protocol: https             # network: tcp | udp | tls; application: http | https
        bind: 0.0.0.0
        certificates: [{cert: /tls/a.crt, key: /tls/a.key, server_names: ["*.example.com"]}]
        timeouts: {connect: 5, idle: 60, response: 60, client_header: 30}
        max_connections: 10000
        default_action: {forward: web}
        rules:
          - priority: 10
            conditions: {host: ["api.example.com"], path: ["/v2/*"], header: {X-Canary: ["true"]},
                         method: [GET, POST], query: {beta: ["1"]}, source_ip: ["10.0.0.0/8"]}
            action:
              forward: [{target_group: api-v1, weight: 90}, {target_group: api-v2, weight: 10}]
          - priority: 20
            conditions: {path: ["/old/*"]}
            action: {redirect: {status: 301, location: "https://{host}/new{path}?{query}"}}
          - priority: 30
            conditions: {path: ["/maintenance"]}
            action: {fixed_response: {status: 503, body: "back soon", content_type: text/plain}}
```

Rules are evaluated by ascending priority; conditions within a rule are AND-ed, values within a condition are OR-ed and support `*`/`?` globs. Host and header values match case-insensitively.

## Admin API

All routes except `/healthz` and `/metrics` need `Authorization: Bearer <token>` when a token is set. Bodies are JSON (or YAML with `Content-Type: application/yaml`).

| Method & path | |
|---|---|
| `GET /healthz`, `GET /metrics` | liveness, Prometheus metrics |
| `GET /state` | listeners, connections, per-target health and load |
| `GET`, `PUT /config` | whole config |
| `GET /load-balancers`, `GET`/`PUT`/`DELETE /load-balancers/{name}` | load balancers |
| `GET /target-groups`, `GET`/`PUT`/`DELETE /target-groups/{name}` | target groups (`GET` includes live status) |
| `GET`, `POST /target-groups/{name}/targets` | list / register a target |
| `PUT`, `DELETE /target-groups/{name}/targets/{host:port}` | change weight / deregister (drains) |

Every change is validated against the *whole* config first (`400` with the exact path of the problem, nothing changes), then applied as a diff: unchanged listeners keep their sockets and connections, target groups keep health state. If applying fails (e.g. a port is taken) the previous config is restored and the API answers `409`.

## Performance

Measured with [`bench/run.sh`](bench/run.sh): a Go backend, [hey](https://github.com/rakyll/hey) with 128 connections, everything on **one laptop** (Intel i7-1355U, 2 performance + 8 efficiency cores) — client, LB and backend compete for the same cores, so treat these as a floor. Ranges are from two runs.

| Path | req/s | p50 |
|---|---:|---:|
| Backend direct (no LB) | 128k–148k | 0.5–0.6 ms |
| ALB (HTTP/1.1, keep-alive), 1 worker | 7.1k–7.6k | ~15 ms |
| ALB, 4 workers | 16k–17.5k | ~8 ms |
| NLB (TCP), 1 worker | 23k | ~6 ms |
| NLB, 4 workers | 48k–58k | ~2 ms |

**Honest positioning:** onprem-lb is written in Python (asyncio + uvloop). It will not match HAProxy, Envoy or NGINX on raw throughput or tail latency, and it is not trying to. It targets the many on-prem services that need *thousands*, not millions, of requests per second and benefit from an ELB-style API, a small readable codebase, and runtime control. Run `bench/run.sh` on your own hardware before deciding.

## Limits

- HTTP/1.1 only towards clients and targets (no HTTP/2, no gRPC-over-h2, no HTTP/3).
- No mTLS client authentication, no rate limiting, no WAF, no response caching or compression.
- Health checks run per worker process (N workers → N× probe traffic); least-connections and round-robin state is per worker.
- UDP health needs a TCP/HTTP check port on the target.
- High availability between two LB machines (VIP failover, e.g. keepalived/VRRP or BGP anycast) is up to you; onprem-lb is a single-node data plane.
- Young project: v0.1.0, tested (unit + real-socket integration + multi-process tests, Python 3.11–3.13) but not yet battle-tested in production.

## Development

```sh
uv venv && uv pip install -e '.[dev,fast]'
pytest                       # 74 tests, real sockets and processes, ~5 s
ruff check src tests
bench/run.sh 10s 128         # needs go and hey
```

Architecture notes: [`docs/design.md`](docs/design.md).

## License

[Apache-2.0](LICENSE)
