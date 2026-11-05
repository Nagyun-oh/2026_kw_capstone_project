#!/usr/bin/env bash
# 탐지 지연(T4): AI가 공격으로 판정하는 같은 공격 샘플 300건(초당 2건)을 세 조건에서 메인 WAF로 보낸다.
#   idle   : 공격만
#   load5  : 정상 부하 초당 3건(k6, WAF 경유) + 공격 2건 = 초당 5건
#   load10 : 정상 부하 초당 8건 + 공격 2건 = 초당 10건
# 공격 요청은 호스트에서 localhost:80으로 보내므로 WAF가 보는 IP는 Docker 게이트웨이다. 이 IP는 블랙리스트
# 동기화에서 제외되므로(waf/sync) 자동 등록이 켜진 백엔드에서도 측정 중 차단되지 않는다.
#
#   bash dev_tools/load-test/run-detection.sh          # 결과: dev_tools/datasets/load-test/detection/
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SCRIPTS=$ROOT/dev_tools/load-test
OUT=${OUT:-$ROOT/dev_tools/datasets/load-test/detection}
K6_IMAGE=grafana/k6:1.0.0
mkdir -p "$OUT"
UIDGID="$(id -u):$(id -g)"
total_lag() {
  docker exec kafka kafka-consumer-groups --bootstrap-server localhost:9092 --describe --all-groups 2>/dev/null \
    | awk '$1 ~ /-group$/ && $6 ~ /^[0-9]+$/ {s += $6} END {print s + 0}'
}
wait_idle() { for _ in $(seq 1 800); do [ "$(total_lag)" = 0 ] && return; sleep 3; done; echo "대기 시간 초과"; }

( docker stats --format '{{json .}}' | while IFS= read -r line; do printf '%s %s\n' "$(date +%s.%N)" "$line"; done ) > "$OUT/stats.log" 2>&1 &
STATS_PID=$!

for cond in idle load5 load10; do
  wait_idle; sleep 5
  case $cond in idle) rate=0;; load5) rate=3;; load10) rate=8;; esac
  if [ "$rate" != 0 ]; then
    mkdir -p "$OUT/$cond-k6"
    docker run -d --rm --name "k6-det-$cond" --network security-net --user "$UIDGID" -v "$SCRIPTS:/scripts:ro" \
      -v "$OUT/$cond-k6:/out" -e BASE=http://waf:8080 -e RATE=$rate -e DURATION=165s -e RUN=det-$cond -e TARGET=waf \
      $K6_IMAGE run --quiet --out csv=/out/raw.csv /scripts/waf-latency.js > /dev/null
    sleep 5
  fi
  echo "$(date +%T) $cond 시작 (정상 부하 초당 $rate건)"
  python3 "$SCRIPTS/detection_latency.py" "det$cond$(date +%H%M)" 300 2 "$OUT/$cond" > "$OUT/$cond.log" 2>&1
  echo "$(date +%T) $cond 완료"; tail -9 "$OUT/$cond.log"
done
pkill -P $STATS_PID; kill $STATS_PID 2>/dev/null
echo "끝 $(date +%T)"
