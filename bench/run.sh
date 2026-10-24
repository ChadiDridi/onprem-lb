#!/usr/bin/env bash
# Reproducible benchmark: Go backend, onprem-lb in front, hey as the client.
# Needs: go, hey (go install github.com/rakyll/hey@v0.1.4), onprem-lb installed.
# Usage: bench/run.sh [duration] [connections]
set -euo pipefail
cd "$(dirname "$0")"
DUR=${1:-10s}; CONC=${2:-64}
WORK=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$WORK"' EXIT

(cd "$WORK" && cp "$OLDPWD/backend.go" . && go mod init bench >/dev/null 2>&1 && go build -o backend .)
"$WORK/backend" 17001 17002 & sleep 0.5

cat > "$WORK/lb.yaml" <<YAML
admin: {listen: 127.0.0.1:17900}
target_groups:
  http: {protocol: http, algorithm: round_robin, health_check: {protocol: none}, targets: [127.0.0.1:17001]}
  tcp:  {protocol: tcp,  algorithm: round_robin, health_check: {protocol: none}, targets: [127.0.0.1:17001]}
load_balancers:
  alb: {type: application, listeners: [{port: 17080, bind: 127.0.0.1, protocol: http, default_action: {forward: http}}]}
  nlb: {type: network, listeners: [{port: 17090, bind: 127.0.0.1, protocol: tcp, default_action: {forward: tcp}}]}
YAML

report() { # name url
  out=$(hey -z "$DUR" -c "$CONC" "$2")
  rps=$(awk '/Requests\/sec/ {printf "%.0f", $2}' <<<"$out")
  p50=$(awk '/50% in/ {printf "%.2f", $3*1000}' <<<"$out")
  p99=$(awk '/99% in/ {printf "%.2f", $3*1000}' <<<"$out")
  err=$(awk '/Error distribution/ {e=1} END {print e?"errors!":"ok"}' <<<"$out")
  printf "| %-28s | %8s | %7s ms | %7s ms | %s |\n" "$1" "$rps" "$p50" "$p99" "$err"
}

echo "| path | req/s | p50 | p99 | errors |"
echo "|---|---:|---:|---:|---|"
report "direct (no LB)" http://127.0.0.1:17001/
for mode in "1 uvloop" "1 asyncio" "4 uvloop" "8 uvloop"; do
  set -- $mode; workers=$1; loop=$2
  flag=""; [ "$loop" = asyncio ] && flag="--no-uvloop"
  onprem-lb serve -c "$WORK/lb.yaml" --no-access-log --log-level warning --workers "$workers" $flag & pid=$!
  for i in $(seq 50); do curl -sf 127.0.0.1:17080/ >/dev/null && break; sleep 0.1; done
  report "ALB http, $workers worker(s), $loop" http://127.0.0.1:17080/
  report "NLB tcp, $workers worker(s), $loop" http://127.0.0.1:17090/
  kill $pid; wait $pid 2>/dev/null || true
done
