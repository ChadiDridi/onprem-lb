# Changelog

## 0.1.0

First release.
- Network LB: TCP, UDP and TLS listeners, with PROXY protocol v1/v2.
- Application LB: HTTP/HTTPS with rules and forward, redirect and fixed-response actions, weighted target groups, stickiness, and WebSocket support.
- 11 balancing algorithms, including Maglev and consistent hashing.
- Health checks, passive ejection and draining.
- Admin REST API with atomic apply and rollback, plus a state file.
- Multi-core workers via SO_REUSEPORT.
- Prometheus metrics and a Docker image.
