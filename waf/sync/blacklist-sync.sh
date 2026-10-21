#!/usr/bin/env bash
# 백엔드 블랙리스트(GET /internal/waf/blacklist)를 ModSecurity 차단 룰로 바꿔 WAF에 적용한다.
#
#   init-volume  상태 볼륨을 준비한다 (root, waf-blacklist-init 컨테이너에서 실행)
#   prepare      nginx 시작 직전에 저장된 룰을 확인한다 (99-blacklist-sync.sh에서 실행)
#   run          주기 동기화 루프 (99-blacklist-sync.sh가 백그라운드로 실행)
#   once         한 번만 동기화한다 (수동 점검용)
#
# 동기화 흐름: 스냅샷 조회 -> version 비교 -> IP 검증·제외 -> 룰 생성 -> nginx -t -> 교체 -> reload 확인
# 조회·검증·적용 중 하나라도 실패하면 기존 룰을 그대로 둔다(마지막 정상 설정 유지).
# 정상 응답의 빈 목록은 "차단할 IP 없음"으로 보고 기존 차단을 해제한다.
set -uo pipefail
shopt -s nullglob
export LC_ALL=C

STATE_DIR=${WAF_BLACKLIST_STATE_DIR:-/var/lib/waf-blacklist}
RULES_FILE=$STATE_DIR/blacklist.conf   # CUSTOM-003-blacklist-sync.conf가 Include하는 파일
SYNC_URL=${WAF_SYNC_URL:-http://backend:8080/internal/waf/blacklist}
SYNC_TOKEN=${WAF_SYNC_TOKEN:-}
SYNC_INTERVAL=${WAF_SYNC_INTERVAL:-10}
EXCLUDE_IPS=${WAF_SYNC_EXCLUDE_IPS:-}
NGINX_PID_FILE=${WAF_NGINX_PID_FILE:-/tmp/nginx.pid}
PROC_DIR=${WAF_PROC_DIR:-/proc}
LOCK_DIR=${TMPDIR:-/tmp}
NGINX_UID=101

# MODSEC_RULE_ENGINE=DetectionOnly에서는 deny가 실행되지 않는다.
# ctl:ruleEngine=On은 이 룰에 걸린 요청에서만 엔진을 켜므로 나머지 CRS 판정은 계속 탐지만 한다.
RULE_PREFIX='SecRule REMOTE_ADDR "@ipMatch '
RULE_SUFFIX="\" \"id:20100,phase:1,deny,status:403,log,msg:'Blacklisted IP (backend sync)',tag:'custom/blacklist',ctl:ruleEngine=On\""
EMPTY_RULES='# 차단할 IP가 없다(동기화 전이거나 블랙리스트가 비어 있음).'

LAST_VERSION=''
UNCHANGED=0
SYNC_ERROR='' FETCH_ERROR='' APPLY_ERROR='' RELOAD_ERROR=''
declare -A PROTECTED=()

log() { printf '%s [blacklist-sync] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

# 로그에 남길 때 백엔드가 준 값의 제어 문자 등을 지운다.
printable() { local s=${1//[^0-9A-Za-z.:\/_-]/?}; printf '%s' "${s:0:64}"; }

# ---------------------------------------------------------------- IP 검증

is_ipv4() {
    local o='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
    local re="^$o\\.$o\\.$o\\.$o\$"
    [[ $1 =~ $re ]]
}

# ':'로 이어진 IPv6 그룹 수를 출력한다. 그룹 형식이 틀리면 실패한다.
ipv6_group_count() {
    local part count=0
    if [[ -z $1 ]]; then echo 0; return 0; fi
    [[ $1 == :* || $1 == *: ]] && return 1
    local IFS=:
    for part in $1; do
        [[ $part =~ ^[0-9a-f]{1,4}$ ]] || return 1
        count=$((count + 1))
    done
    echo "$count"
}

# 소문자 IPv6만 허용한다. IPv4 포함 표기(::ffff:1.2.3.4)와 CIDR은 허용하지 않는다.
is_ipv6() {
    local ip=$1 head tail h t
    [[ ${#ip} -le 39 && $ip == *:* && $ip =~ ^[0-9a-f:]+$ ]] || return 1
    if [[ $ip == *::* ]]; then
        head=${ip%%::*}
        tail=${ip#*::}
        [[ $tail != *::* ]] || return 1
        h=$(ipv6_group_count "$head") || return 1
        t=$(ipv6_group_count "$tail") || return 1
        (( h + t <= 7 ))
    else
        h=$(ipv6_group_count "$ip") || return 1
        (( h == 8 ))
    fi
}

is_ip() { is_ipv4 "$1" || is_ipv6 "$1"; }

# 컨테이너 기본 게이트웨이. 호스트(로컬 테스트, AWS 호스트 Nginx)에서 들어온 요청의 출발지다.
default_gateway() {
    local hex
    hex=$(awk '$2 == "00000000" { print $3; exit }' "$PROC_DIR/net/route" 2>/dev/null)
    [[ $hex =~ ^[0-9A-Fa-f]{8}$ ]] || return 1
    printf '%d.%d.%d.%d' "0x${hex:6:2}" "0x${hex:4:2}" "0x${hex:2:2}" "0x${hex:0:2}"
}

# 차단하면 모든 요청이나 내부 통신이 막히는 IP. 127.0.0.0/8은 is_protected에서 따로 확인한다.
load_protected() {
    local ip gateway
    local -a items=()
    for ip in 0.0.0.0 :: ::1; do PROTECTED[$ip]=고정; done
    if gateway=$(default_gateway); then PROTECTED[$gateway]=게이트웨이; fi
    # 신뢰 프록시(SET_REAL_IP_FROM)가 단일 IP면 함께 제외한다. CIDR이면 WAF_SYNC_EXCLUDE_IPS로 지정한다.
    ip=${SET_REAL_IP_FROM:-}
    ip=${ip,,}
    if is_ip "$ip"; then PROTECTED[$ip]=신뢰프록시; fi
    IFS=', ' read -ra items <<< "$EXCLUDE_IPS"
    for ip in "${items[@]}"; do
        ip=${ip,,}
        if is_ip "$ip"; then
            PROTECTED[$ip]=설정
        else
            log "경고: WAF_SYNC_EXCLUDE_IPS의 '$(printable "$ip")'는 단일 IP가 아니어서 무시한다"
        fi
    done
}

is_protected() { [[ $1 == 127.* || -n ${PROTECTED[$1]+x} ]]; }

protected_summary() {
    local ip out='127.0.0.0/8'
    for ip in "${!PROTECTED[@]}"; do out+=", $ip(${PROTECTED[$ip]})"; done
    printf '%s' "$out"
}

# ---------------------------------------------------------------- 스냅샷 조회·해석

# $1 파일에 응답 본문을 저장한다. 실패 이유는 FETCH_ERROR에 남긴다.
fetch_snapshot() {
    local out=$1 header code rc
    header=$(mktemp) || { FETCH_ERROR='임시 파일 생성 실패'; return 1; }
    # 토큰이 프로세스 인자에 보이지 않도록 헤더를 파일로 넘긴다.
    printf 'X-WAF-Sync-Token: %s\n' "$SYNC_TOKEN" > "$header"
    code=$(curl -s -o "$out" -w '%{http_code}' --connect-timeout 3 --max-time 10 \
        -H "@$header" "$SYNC_URL")
    rc=$?
    rm -f "$header"
    if (( rc != 0 )); then FETCH_ERROR="연결 실패(curl 종료 코드 $rc)"; return 1; fi
    if [[ $code != 200 ]]; then FETCH_ERROR="HTTP $code"; return 1; fi
}

# {"version":"<sha256>","ipAddresses":["..."]} 형식만 받아 VERSION, RAW_IPS를 채운다.
parse_snapshot() {
    local body list item
    local -a items=()
    local re_version='"version":"([0-9a-f]{64})"'
    local re_ips='"ipAddresses":\[([^]]*)\]'
    local re_item='^"([^"\\]*)"$'
    body=$(tr -d ' \t\r\n' < "$1")
    [[ $body == \{*\} && $body =~ $re_version ]] || return 1
    VERSION=${BASH_REMATCH[1]}
    [[ $body =~ $re_ips ]] || return 1
    list=${BASH_REMATCH[1]}
    RAW_IPS=()
    [[ -z $list ]] && return 0
    IFS=, read -ra items <<< "$list"
    for item in "${items[@]}"; do
        [[ $item =~ $re_item ]] || return 1
        RAW_IPS+=("${BASH_REMATCH[1]}")
    done
}

# RAW_IPS에서 형식이 틀리거나 차단하면 안 되는 IP, 중복을 빼고 BLOCK_IPS를 만든다.
select_ips() {
    local ip
    local -A seen=()
    local -a invalid=() skipped=()
    BLOCK_IPS=()
    for ip in "${RAW_IPS[@]}"; do
        ip=${ip,,}
        if ! is_ip "$ip"; then invalid+=("$(printable "$ip")"); continue; fi
        if is_protected "$ip"; then skipped+=("$ip"); continue; fi
        [[ -n ${seen[$ip]+x} ]] && continue
        seen[$ip]=1
        BLOCK_IPS+=("$ip")
    done
    if (( ${#invalid[@]} > 0 )); then log "IP 형식이 아니어서 제외: ${invalid[*]}"; fi
    if (( ${#skipped[@]} > 0 )); then log "차단하면 안 되는 IP라서 제외: ${skipped[*]}"; fi
    return 0
}

# ---------------------------------------------------------------- 룰 파일

render_rules() {
    local joined
    {
        printf '# 자동 생성: waf/sync/blacklist-sync.sh (백엔드 version %s). 직접 수정하지 않는다.\n' "$VERSION"
        if (( ${#BLOCK_IPS[@]} == 0 )); then
            printf '%s\n' "$EMPTY_RULES"
        else
            joined=$(IFS=,; printf '%s' "${BLOCK_IPS[*]}")
            printf '%s%s%s\n' "$RULE_PREFIX" "$joined" "$RULE_SUFFIX"
        fi
    } > "$1"
}

# 룰 파일에 들어 있는 IP를 한 줄에 하나씩 출력한다.
rule_ips() {
    local line
    [[ -r $1 ]] || return 0
    while IFS= read -r line || [[ -n $line ]]; do
        [[ $line == "$RULE_PREFIX"*"$RULE_SUFFIX" ]] || continue
        line=${line#"$RULE_PREFIX"}
        line=${line%"$RULE_SUFFIX"}
        tr ',' '\n' <<< "$line"
    done < "$1"
}

# 이 스크립트가 만든 형식(주석 + SecRule 최대 1줄, 올바른 IP만)인지 확인한다.
rules_file_valid() {
    local line list ip rules=0
    local -a ips=()
    while IFS= read -r line || [[ -n $line ]]; do
        [[ -z $line || $line == '#'* ]] && continue
        [[ $line == "$RULE_PREFIX"*"$RULE_SUFFIX" ]] || return 1
        rules=$((rules + 1))
        (( rules == 1 )) || return 1
        list=${line#"$RULE_PREFIX"}
        list=${list%"$RULE_SUFFIX"}
        IFS=, read -ra ips <<< "$list"
        (( ${#ips[@]} > 0 )) || return 1
        for ip in "${ips[@]}"; do is_ip "$ip" || return 1; done
    done < "$RULES_FILE"
}

# ---------------------------------------------------------------- nginx 적용

nginx_running() {
    local pid
    pid=$(cat "$NGINX_PID_FILE" 2>/dev/null) && [[ $pid =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null
}

# 요청을 처리 중인 worker PID. reload 후 종료 중인 worker는 이름이 바뀌어 제외된다.
worker_pids() {
    local f
    for f in "$PROC_DIR"/[0-9]*/cmdline; do
        # 확인 중에 끝난 프로세스의 파일 열기 오류는 무시한다(2>/dev/null을 먼저 둔다).
        if [[ $(tr -d '\0' 2>/dev/null < "$f") == 'nginx: worker process' ]]; then
            f=${f%/cmdline}
            printf '%s\n' "${f##*/}"
        fi
    done
}

# reload 신호를 보내고, 기존 worker가 모두 새 worker로 바뀌었는지 확인한다.
reload_nginx() {
    local before after output
    before=$(worker_pids | sort)
    if ! output=$(nginx -s reload 2>&1); then
        RELOAD_ERROR=$(grep -m1 -oE '\[(emerg|alert|error)\].*' <<< "$output" | cut -c1-200)
        return 1
    fi
    # worker를 볼 수 없는 환경(테스트 등)에서는 신호 전송 성공까지만 확인한다.
    [[ -n $before ]] || return 0
    for _ in {1..20}; do
        sleep 0.5
        after=$(worker_pids | sort)
        if [[ -n $after && -z $(comm -12 <(printf '%s\n' "$before") <(printf '%s\n' "$after")) ]]; then
            return 0
        fi
    done
    RELOAD_ERROR='10초 안에 새 worker가 확인되지 않음'
    return 1
}

# $1(RULES_FILE과 같은 디렉터리의 새 룰)을 검증 후 교체한다. 실패하면 이전 파일로 되돌린다.
apply_rules() {
    local candidate=$1 backup=$RULES_FILE.prev output
    cp -p "$RULES_FILE" "$backup" 2>/dev/null || printf '%s\n' "$EMPTY_RULES" > "$backup"
    mv -f "$candidate" "$RULES_FILE"
    if ! output=$(nginx -t 2>&1); then
        mv -f "$backup" "$RULES_FILE"
        APPLY_ERROR="nginx -t 실패: $(grep -m1 -oE '\[emerg\].*' <<< "$output" | cut -c1-200)"
        return 1
    fi
    # nginx가 아직 뜨지 않았으면 파일만 바꿔 두고, nginx가 시작할 때 읽게 한다.
    if nginx_running && ! reload_nginx; then
        mv -f "$backup" "$RULES_FILE"
        APPLY_ERROR="reload 실패: $RELOAD_ERROR"
        return 1
    fi
    rm -f "$backup"
}

# 추가·해제된 IP를 로그 한 줄로 요약한다(많으면 앞의 10개만). $1, $2: 정렬된 IP 목록
summarize_change() {
    local added removed
    added=$(comm -13 <(printf '%s\n' "$1" | sed '/^$/d') <(printf '%s\n' "$2" | sed '/^$/d') | head -10 | paste -sd, -)
    removed=$(comm -23 <(printf '%s\n' "$1" | sed '/^$/d') <(printf '%s\n' "$2" | sed '/^$/d') | head -10 | paste -sd, -)
    printf '추가 [%s] 해제 [%s]' "${added:-없음}" "${removed:-없음}"
}

# 0: 적용 완료 또는 변경 없음, 1: 실패(SYNC_ERROR, 기존 룰 유지)
sync_once() {
    local response candidate old_ips new_ips
    response=$(mktemp) || { SYNC_ERROR='임시 파일 생성 실패'; return 1; }
    if ! fetch_snapshot "$response"; then
        rm -f "$response"; SYNC_ERROR="목록 조회 실패: $FETCH_ERROR"; return 1
    fi
    if ! parse_snapshot "$response"; then
        rm -f "$response"; SYNC_ERROR='응답 형식이 올바르지 않음'; return 1
    fi
    rm -f "$response"

    # version이 같으면 목록이 바뀌지 않았으므로 룰을 다시 만들지 않는다.
    if [[ $VERSION == "$LAST_VERSION" ]]; then UNCHANGED=1; return 0; fi

    select_ips
    candidate=$RULES_FILE.new
    if ! render_rules "$candidate" 2>/dev/null; then
        rm -f "$candidate"; SYNC_ERROR="룰 파일을 쓸 수 없음($STATE_DIR)"; return 1
    fi
    # 재시작 직후처럼 이미 같은 룰이 적용돼 있으면 reload하지 않는다.
    if cmp -s "$candidate" "$RULES_FILE"; then
        rm -f "$candidate"; LAST_VERSION=$VERSION; UNCHANGED=1; return 0
    fi

    old_ips=$(rule_ips "$RULES_FILE" | sort)
    new_ips=$(rule_ips "$candidate" | sort)
    if ! apply_rules "$candidate"; then
        rm -f "$candidate"; SYNC_ERROR=$APPLY_ERROR; return 1
    fi
    LAST_VERSION=$VERSION
    UNCHANGED=0
    log "적용 완료: 차단 IP ${#BLOCK_IPS[@]}개, $(summarize_change "$old_ips" "$new_ips")"
}

# 같은 컨테이너에서 run과 once가 동시에 파일을 바꾸지 않도록 동기화 한 번마다 잠근다.
locked_sync() {
    local rc
    if ! flock -w 30 8; then SYNC_ERROR='다른 동기화가 끝나지 않음'; return 1; fi
    sync_once
    rc=$?
    flock -u 8
    return "$rc"
}

# ---------------------------------------------------------------- 실행 모드

init_volume() {
    mkdir -p "$STATE_DIR"
    [[ -s $RULES_FILE ]] || printf '%s\n' "$EMPTY_RULES" > "$RULES_FILE"
    chown -R "$NGINX_UID:$NGINX_UID" "$STATE_DIR"
    log "상태 볼륨 준비 완료: $STATE_DIR"
}

prepare() {
    if [[ ! -w $STATE_DIR ]]; then
        log "경고: $STATE_DIR에 쓸 수 없다. waf-blacklist-init 실행 여부와 볼륨 권한을 확인한다"
        return 0
    fi
    rm -f "$RULES_FILE.new" "$RULES_FILE.prev"
    if [[ ! -s $RULES_FILE ]]; then
        printf '%s\n' "$EMPTY_RULES" > "$RULES_FILE"
        log "저장된 룰이 없어 차단 없이 시작한다"
    elif rules_file_valid; then
        log "마지막 정상 룰로 시작한다: 차단 IP $(rule_ips "$RULES_FILE" | grep -c .)개"
    else
        mv -f "$RULES_FILE" "$RULES_FILE.invalid"
        printf '%s\n' "$EMPTY_RULES" > "$RULES_FILE"
        log "경고: 저장된 룰 형식이 올바르지 않아 $RULES_FILE.invalid로 옮기고 차단 없이 시작한다"
    fi
}

run_loop() {
    local last_error='' failures=0
    exec 9>"$LOCK_DIR/waf-blacklist-sync.loop.lock" 8>"$LOCK_DIR/waf-blacklist-sync.lock" || exit 1
    if ! flock -n 9; then log "이미 동기화 루프가 실행 중이어서 종료한다"; exit 0; fi
    if [[ -z $SYNC_TOKEN ]]; then
        log "WAF_SYNC_TOKEN이 비어 있어 동기화하지 않는다. 저장된 룰만 사용한다"
        exit 0
    fi
    if [[ ! $SYNC_INTERVAL =~ ^[1-9][0-9]*$ ]]; then
        log "경고: WAF_SYNC_INTERVAL이 올바르지 않아 10초를 사용한다"
        SYNC_INTERVAL=10
    fi
    load_protected
    log "동기화 시작: $SYNC_URL, ${SYNC_INTERVAL}초 간격, 차단 제외: $(protected_summary)"
    # 훅은 nginx 시작 전에 실행되므로 reload할 수 있을 때까지 최대 60초 기다린다.
    for _ in {1..60}; do nginx_running && break; sleep 1; done

    while true; do
        if locked_sync; then
            if [[ -n $last_error ]]; then
                log "동기화 복구: 실패 ${failures}회 뒤 정상 조회"
                last_error=''
                failures=0
            fi
        else
            failures=$((failures + 1))
            # 같은 오류가 반복되면 처음 한 번만 남긴다.
            if [[ $SYNC_ERROR != "$last_error" ]]; then
                log "동기화 실패, 기존 룰 유지: $SYNC_ERROR"
                last_error=$SYNC_ERROR
            fi
        fi
        sleep "$SYNC_INTERVAL"
    done
}

run_once() {
    exec 8>"$LOCK_DIR/waf-blacklist-sync.lock" || exit 1
    if [[ -z $SYNC_TOKEN ]]; then log 'WAF_SYNC_TOKEN이 비어 있다'; exit 1; fi
    load_protected
    if ! locked_sync; then log "동기화 실패, 기존 룰 유지: $SYNC_ERROR"; exit 1; fi
    if (( UNCHANGED )); then
        log "변경 없음: 차단 IP $(rule_ips "$RULES_FILE" | grep -c .)개 유지"
    fi
}

case ${1:-} in
    init-volume) init_volume ;;
    prepare) prepare ;;
    run) run_loop ;;
    once) run_once ;;
    *) echo "사용법: $0 {init-volume|prepare|run|once}" >&2; exit 2 ;;
esac
