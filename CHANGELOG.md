# Changelog

## 0.1.1

- GitHub Action (`uses: ChadiDridi/onprem-lb@v0.1.1`), with two modes:
  - `mode: validate` lints load balancer configs in PRs.
  - `mode: serve` runs a real onprem-lb in CI so integration tests go through an actual L4/L7 load balancer.

## 0.1.0

First release.
- Network LB: TCP, UDP and TLS listeners, with PROXY protocol v1/v2.
- Application LB: HTTP/HTTPS with rules and forward, redirect and fixed-response actions, weighted target groups, stickiness, and WebSocket support.
- 11 balancing algorithms, including Maglev and consistent hashing.
- Health checks, passive ejection and draining.
- Admin REST API with atomic apply and rollback, plus a state file.
- Multi-core workers via SO_REUSEPORT.
- Prometheus metrics and a Docker image.
