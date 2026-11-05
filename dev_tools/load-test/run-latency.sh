#!/usr/bin/env bash
# 사용자 응답 지연(T4) + 자원 사용량(T3): JuiceShop 직접 vs WAF 경유 × RPS 단계 × 반복, 단계마다 60초.
# 메인 스택(compose.yaml)이 떠 있어야 한다. k6는 security-net 안에서 juiceshop:3000 / waf:8080으로 보낸다.
#
# 매 실행 전에 파이프라인(모든 Kafka 소비 그룹 lag)이 빌 때까지 기다린다. AI가 밀린 로그를 처리하는 동안
# 직접 접속을 재면 그 CPU 사용이 결과에 섞이기 때문이다. WAF 경유 실행 뒤에는 밀린 처리가 끝나는 데
# 걸린 시간(drain_s)을 기록한다. WAF 경유 요청은 network_logs에 저장된다(raw_log에 X-Load-Test 헤더).
#
# PAUSE_PIPELINE=1이면 Fluent Bit을 일시 정지해 분석 파이프라인(Kafka·백엔드·AI·MySQL)이 쉬는 상태로 잰다(WAF만 구성).
# 쌓인 로그는 끝날 때 재개하면 그대로 처리된다(Fluent Bit 파일 버퍼·오프셋 DB 사용).
#
#   bash dev_tools/load-test/run-latency.sh            # 결과: dev_tools/datasets/load-test/latency/
#   PAUSE_PIPELINE=1 REPS=1 OUT=dev_tools/datasets/load-test/latency-waf-only bash dev_tools/load-test/run-latency.sh
#   python3 dev_tools/load-test/analyze_latency.py dev_tools/datasets/load-test/latency
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SCRIPTS=$ROOT/dev_tools/load-test
OUT=${OUT:-$ROOT/dev_tools/datasets/load-test/latency}
RATES=${RATES:-"10 50 100"}
REPS=${REPS:-3}
DURATION=${DURATION:-60s}
PAUSE_PIPELINE=${PAUSE_PIPELINE:-0}
K6_IMAGE=grafana/k6:1.0.0
mkdir -p "$OUT"
: > "$OUT/runs.jsonl"
UIDGID="$(id -u):$(id -g)"

mysql_q() { docker exec security-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -D security_db -N -B -e "$0"' "$1"; }
total_lag() {
  docker exec kafka kafka-consumer-groups --bootstrap-server localhost:9092 --describe --all-groups 2>/dev/null \
    | awk '$1 ~ /-group$/ && $6 ~ /^[0-9]+$/ {s += $6} END {print s + 0}'
}
offsets() {  # log-topic, ai-request-topic, ai-result-topic 끝 offset
  docker exec kafka kafka-run-class kafka.tools.GetOffsetShell --bootstrap-server localhost:9092 2>/dev/null \
    | awk -F: '$1=="log-topic"{a=$3} $1=="ai-request-topic"{b=$3} $1=="ai-result-topic"{c=$3} END{printf "[%d,%d,%d]", a, b, c}'
}
wait_drain() {  # lag이 0이 될 때까지(최대 40분) 기다리고 걸린 초를 출력한다.
  local t0 lag
  t0=$(date +%s)
  while :; do
    lag=$(total_lag)
    [ "$lag" = 0 ] && break
    if [ $(( $(date +%s) - t0 )) -ge 2400 ]; then echo "drain 시간 초과(lag $lag)" >&2; break; fi
    sleep 3
  done
  echo $(( $(date +%s) - t0 ))
}

# 자원 사용량: docker stats 스트림(약 1초 간격)에 시각을 붙여 기록한다.
( docker stats --format '{{json .}}' | while IFS= read -r line; do printf '%s %s\n' "$(date +%s.%N)" "$line"; done ) > "$OUT/stats.log" 2>&1 &
STATS_PID=$!

run_k6() {  # name target rate duration
  local name=$1 target=$2 rate=$3 dur=$4 base pre drain=0 off0 off1 start end bl
  [ "$target" = waf ] && base=http://waf:8080 || base=http://juiceshop:3000
  pre=$(wait_drain)
  sleep 5
  off0=$(offsets)
  mkdir -p "$OUT/$name"
  start=$(date +%s.%N)
  docker run --rm --name "k6-$name" --network security-net --user "$UIDGID" -v "$SCRIPTS:/scripts:ro" -v "$OUT/$name:/out" \
    -e BASE=$base -e RATE=$rate -e DURATION=$dur -e RUN=$name -e TARGET=$target \
    $K6_IMAGE run --quiet --out csv=/out/raw.csv /scripts/waf-latency.js > "$OUT/$name/summary.txt" 2>&1
  end=$(date +%s.%N)
  [ "$target" = waf ] && [ "$PAUSE_PIPELINE" != 1 ] && drain=$(wait_drain)
  off1=$(offsets)
  bl=$(mysql_q "SELECT COUNT(*) FROM ip_blacklist")
  printf '{"name":"%s","target":"%s","rate":%s,"start":%s,"end":%s,"pre_wait_s":%s,"drain_s":%s,"offsets_start":%s,"offsets_end":%s,"blacklist":%s,"pipeline_paused":%s}\n' \
    "$name" "$target" "$rate" "$start" "$end" "$pre" "$drain" "$off0" "$off1" "$bl" "$PAUSE_PIPELINE" >> "$OUT/runs.jsonl"
  echo "$(date +%T) $name 완료 (사전 대기 ${pre}s, drain ${drain}s, blacklist $bl)"
  # 블랙리스트가 늘면 k6 IP가 자동 등록됐을 수 있다(이후 실행이 403으로 깨진다).
  if [ "$bl" != "$BL0" ]; then echo "블랙리스트가 바뀌어 중단합니다 ($BL0 -> $bl)"; pkill -P $STATS_PID; kill $STATS_PID; exit 1; fi
}

BL0=$(mysql_q "SELECT COUNT(*) FROM ip_blacklist")
echo "시작 $(date +%T): blacklist $BL0, network_logs max id $(mysql_q "SELECT COALESCE(MAX(id),0) FROM network_logs")"
if [ "$PAUSE_PIPELINE" = 1 ]; then
  wait_drain > /dev/null
  docker pause waf-fluent-bit > /dev/null && echo "Fluent Bit 일시 정지(분석 파이프라인 정지)"
  trap 'docker unpause waf-fluent-bit > /dev/null 2>&1 && echo "Fluent Bit 재개"' EXIT
fi
run_k6 warm-direct direct 10 10s
run_k6 warm-waf waf 10 10s
for rep in $(seq 1 "$REPS"); do
  for rate in $RATES; do
    # 회차마다 직접/WAF 순서를 번갈아 시간에 따른 변화가 한쪽에 몰리지 않게 한다.
    if [ $((rep % 2)) = 0 ]; then order="waf direct"; else order="direct waf"; fi
    for target in $order; do
      run_k6 "r${rep}-${target}-${rate}" "$target" "$rate" "$DURATION"
    done
  done
done
pkill -P $STATS_PID; kill $STATS_PID 2>/dev/null
echo "끝 $(date +%T): network_logs max id $(mysql_q "SELECT MAX(id) FROM network_logs")"
