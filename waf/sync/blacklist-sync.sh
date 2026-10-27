#!/usr/bin/env bash
# 백엔드 블랙리스트(GET /internal/waf/blacklist)를 ModSecurity 차단 룰로 바꿔 WAF에 적용한다.
#
#   init-volume  상태 볼륨을 준비한다 (root, waf-blacklist-init 컨테이너에서 실행)
#   prepare      nginx 시작 직전에 저장된 룰을 확인한다 (99-blacklist-sync.sh에서 실행)
#   run          주기 동기화 루프 (99-blacklist-sync.sh가 백그라운드로 실행)
#   once         한 번만 동기화한다 (수동 점검용)
#
# 동기화 흐름: 스냅샷 조회 -> JSON 검증 -> version 비교 -> IP 검증·제외 -> 룰 생성
#              -> 백업 -> 교체 -> nginx -t -> reload 확인 -> 백업 삭제
# 조회·검증·적용 중 하나라도 실패하면 기존 룰을 그대로 둔다(마지막 정상 설정 유지).
# 적용 중에는 백업(blacklist.conf.prev)이 마지막 정상 룰이다. 백업이 남아 있으면 적용이 끝나지 않은
# 것이므로 다음 동기화나 재시작 때 백업으로 되돌린다. 적용에 실패하면 다음 주기에 반드시 다시 적용한다.
# 정상 응답의 빈 목록은 "차단할 IP 없음"으로 보고 기존 차단을 해제한다.
set -uo pipefail
shopt -s nullglob
export LC_ALL=C

STATE_DIR=${WAF_BLACKLIST_STATE_DIR:-/var/lib/waf-blacklist}
RULES_FILE=$STATE_DIR/blacklist.conf   # CUSTOM-003-blacklist-sync.conf가 Include하는 파일
CANDIDATE_FILE=$RULES_FILE.new         # 검증 전 새 룰
BACKUP_FILE=$RULES_FILE.prev           # 적용·복구가 끝날 때까지 보존하는 마지막 정상 룰
RESTORE_FILE=$RULES_FILE.restore       # 백업을 보존하며 원자적으로 복원할 임시 파일
SYNC_URL=${WAF_SYNC_URL:-http://backend:8080/internal/waf/blacklist}
SYNC_TOKEN=${WAF_SYNC_TOKEN:-}
SYNC_INTERVAL=${WAF_SYNC_INTERVAL:-10}
EXCLUDE_IPS=${WAF_SYNC_EXCLUDE_IPS:-}
NGINX_PID_FILE=${WAF_NGINX_PID_FILE:-/tmp/nginx.pid}
PROC_DIR=${WAF_PROC_DIR:-/proc}
RELOAD_TIMEOUT=${WAF_RELOAD_TIMEOUT:-10}   # reload 후 새 worker를 기다리는 시간(초)
[[ $RELOAD_TIMEOUT =~ ^[1-9][0-9]*$ ]] || RELOAD_TIMEOUT=10
LOCK_DIR=${TMPDIR:-/tmp}
NGINX_UID=101

# MODSEC_RULE_ENGINE=DetectionOnly에서는 deny가 실행되지 않는다.
# ctl:ruleEngine=On은 이 룰에 걸린 요청에서만 엔진을 켜므로 나머지 CRS 판정은 계속 탐지만 한다.
RULE_PREFIX='SecRule REMOTE_ADDR "@ipMatch '
RULE_SUFFIX="\" \"id:20100,phase:1,deny,status:403,log,msg:'Blacklisted IP (backend sync)',tag:'custom/blacklist',ctl:ruleEngine=On\""
EMPTY_RULES='# 차단할 IP가 없다(동기화 전이거나 블랙리스트가 비어 있음).'

LAST_VERSION=''
FORCE_APPLY=0   # 1이면 version·파일이 같아도 다시 적용한다(이전 적용 실패·중단 뒤 실제 설정과 맞추기)
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

# 응답 본문 전체를 JSON으로 해석해 {"version":"<sha256>","ipAddresses":["..."]} 형식인지 확인하고
# VERSION, RAW_IPS를 채운다. 문법 오류, 필드 누락, 타입 불일치(문자열이 아닌 version·IP)는 모두 실패다.
# 정규식으로는 깨진 JSON을 걸러낼 수 없어 WAF 이미지에 포함된 perl JSON::PP로 해석한다.
# 다른 필드가 더 있어도 무시한다(백엔드 응답에 필드가 추가돼도 동기화가 멈추지 않게).
parse_snapshot() {
    local parsed
    parsed=$(perl -MJSON::PP -MB -e '
        # JSON 문자열만 참. 숫자는 IOK/NOK 플래그를 가지므로 문자열과 구분된다.
        sub is_string {
            my $flags = B::svref_2object(\$_[0])->FLAGS;
            return defined $_[0] && !ref $_[0]
                && ($flags & B::SVp_POK) && !($flags & (B::SVp_IOK | B::SVp_NOK));
        }
        local $/;
        my $data = eval { JSON::PP->new->utf8->decode(<STDIN>) };
        exit 1 unless ref $data eq "HASH";
        my ($version, $ips) = @$data{qw(version ipAddresses)};
        exit 1 unless is_string($version) && $version =~ /\A[0-9a-f]{64}\z/;
        exit 1 unless ref $ips eq "ARRAY";
        for my $ip (@$ips) {
            exit 1 unless is_string($ip) && $ip !~ /[\x00-\x1f]/;   # 줄 단위 출력을 깨는 제어 문자 거부
        }
        binmode STDOUT, ":utf8";
        print join("\n", $version, @$ips);
    ' < "$1" 2>/dev/null) || return 1
    VERSION=${parsed%%$'\n'*}
    RAW_IPS=()
    if [[ $parsed == *$'\n'* ]]; then mapfile -t RAW_IPS <<< "${parsed#*$'\n'}"; fi
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
# 0: 확인 완료, 1: 신호 전송 실패(기존 설정 유지), 2: 신호는 보냈지만 시간 안에 확인 못 함(적용 여부 모름)
reload_nginx() {
    local before after output i
    before=$(worker_pids | sort)
    if ! output=$(nginx -s reload 2>&1); then
        RELOAD_ERROR=$(grep -m1 -oE '\[(emerg|alert|error)\].*' <<< "$output" | cut -c1-200)
        return 1
    fi
    # worker를 볼 수 없는 환경(테스트 등)에서는 신호 전송 성공까지만 확인한다.
    [[ -n $before ]] || return 0
    for (( i = 0; i < RELOAD_TIMEOUT * 2; i++ )); do
        sleep 0.5
        after=$(worker_pids | sort)
        if [[ -n $after && -z $(comm -12 <(printf '%s\n' "$before") <(printf '%s\n' "$after")) ]]; then
            return 0
        fi
    done
    RELOAD_ERROR="${RELOAD_TIMEOUT}초 안에 새 worker가 확인되지 않음"
    return 2
}

# 교체 전 룰을 BACKUP_FILE로 보관한다. 임시 이름에 쓴 뒤 옮겨, 중간에 끊겨도 반쯤 쓰인 백업이 남지 않게 한다.
save_backup() {
    local tmp=$BACKUP_FILE.tmp
    if [[ -e $RULES_FILE ]]; then
        cp -p "$RULES_FILE" "$tmp"
    else
        printf '%s\n' "$EMPTY_RULES" > "$tmp"
    fi || { rm -f "$tmp"; return 1; }
    mv -f "$tmp" "$BACKUP_FILE" || { rm -f "$tmp"; return 1; }
}

# 백업을 복사한 뒤 원자적으로 교체한다. 실행 설정 복구까지 확인하기 전에는 백업을 지우지 않는다.
# 복구 도중 종료돼도 다음 프로세스가 .prev를 보고 다시 복구할 수 있어야 한다.
restore_backup() {
    [[ -e $BACKUP_FILE ]] || return 0
    if ! cp -p "$BACKUP_FILE" "$RESTORE_FILE" || ! mv -f "$RESTORE_FILE" "$RULES_FILE"; then
        rm -f "$RESTORE_FILE"
        return 1
    fi
}

# 미완료 적용은 백엔드 조회와 무관하게 먼저 복구한다. 실패하면 .prev를 남기고 다음 주기에 재시도한다.
recover_pending() {
    local output
    if ! restore_backup; then SYNC_ERROR='끝나지 않은 이전 적용의 파일 복구 실패'; return 1; fi
    if ! output=$(nginx -t 2>&1); then SYNC_ERROR='이전 룰 복구 검증 실패'; return 1; fi
    if nginx_running && ! reload_nginx; then
        SYNC_ERROR="이전 룰 복구 reload 실패(실제 적용 상태 확인 필요): $RELOAD_ERROR"
        return 1
    fi
    if ! rm -f "$BACKUP_FILE"; then SYNC_ERROR='복구 후 백업 삭제 실패'; return 1; fi
    LAST_VERSION=''
    FORCE_APPLY=1
}

# reload 실패 뒤 이전 룰로 되돌린다. $1: reload_nginx 결과
# 신호를 보낸 뒤 확인만 시간 초과됐다면(2) 새 룰이 이미 적용됐거나 적용 중일 수 있으므로,
# 파일만 되돌리지 않고 이전 룰로 다시 검증·reload·확인해 실제 nginx 설정을 파일과 맞춘다.
rollback_reload() {
    local output
    if ! restore_backup; then APPLY_ERROR+=', 이전 룰 복구 실패'; return 1; fi
    if (( $1 == 2 )); then
        if ! output=$(nginx -t 2>&1) || ! reload_nginx; then
            APPLY_ERROR+=', 이전 룰 재적용도 실패(실제 적용 상태 확인 필요)'
            return 1
        fi
        APPLY_ERROR+=', 이전 룰로 다시 reload함'
    fi
    # 신호 전송 자체가 실패했다면 실행 설정은 이전 룰이므로 파일 복원만으로 완료된다.
    if ! rm -f "$BACKUP_FILE"; then APPLY_ERROR+=', 복구 후 백업 삭제 실패'; return 1; fi
}

# $1(RULES_FILE과 같은 디렉터리의 새 룰)을 검증 후 교체한다. 실패하면 이전 룰로 되돌린다.
# 교체부터 완료까지는 BACKUP_FILE이 마지막 정상 룰이며, 적용이 끝나거나 되돌린 뒤에만 사라진다.
# 0: 적용 완료, 1: 실패(APPLY_ERROR)
apply_rules() {
    local candidate=$1 output rc
    if ! save_backup; then APPLY_ERROR='이전 룰 백업 실패'; return 1; fi
    if ! mv -f "$candidate" "$RULES_FILE"; then
        # rename은 원자적이라 실패하면 RULES_FILE은 그대로다. 백업만 지운다.
        rm -f "$BACKUP_FILE"
        APPLY_ERROR='룰 파일 교체 실패'
        return 1
    fi
    if ! output=$(nginx -t 2>&1); then
        APPLY_ERROR="nginx -t 실패: $(grep -m1 -oE '\[emerg\].*' <<< "$output" | cut -c1-200)"
        # reload 전 검증 실패이므로 실행 설정은 바뀌지 않았다.
        if ! restore_backup || ! rm -f "$BACKUP_FILE"; then APPLY_ERROR+=', 이전 룰 복구 실패'; fi
        return 1
    fi
    # nginx가 아직 뜨지 않았으면 파일만 바꿔 두고, nginx가 시작할 때 읽게 한다.
    if nginx_running; then
        reload_nginx
        rc=$?
        if (( rc != 0 )); then
            APPLY_ERROR="reload 실패: $RELOAD_ERROR"
            rollback_reload "$rc"
            return 1
        fi
    fi
    # 백업이 남으면 재시작 때 이전 룰로 되돌아가므로 지우지 못하면 실패로 본다.
    if ! rm -f "$BACKUP_FILE"; then APPLY_ERROR='적용 후 백업 삭제 실패'; return 1; fi
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
    # 이전 적용이 끝나지 않았다면(복구 실패 등) 백업이 마지막 정상 룰이다. 덮어쓰기 전에 먼저 되돌린다.
    if [[ -e $BACKUP_FILE ]]; then
        recover_pending || return 1
        log "끝나지 않은 이전 적용을 마지막 정상 룰로 복구했다. 최신 목록을 조회한다"
    fi
    response=$(mktemp) || { SYNC_ERROR='임시 파일 생성 실패'; return 1; }
    if ! fetch_snapshot "$response"; then
        rm -f "$response"; SYNC_ERROR="목록 조회 실패: $FETCH_ERROR"; return 1
    fi
    if ! parse_snapshot "$response"; then
        rm -f "$response"; SYNC_ERROR='응답 형식이 올바르지 않음'; return 1
    fi
    rm -f "$response"

    # version이 같으면 목록이 바뀌지 않았으므로 룰을 다시 만들지 않는다.
    if (( ! FORCE_APPLY )) && [[ $VERSION == "$LAST_VERSION" ]]; then UNCHANGED=1; return 0; fi

    select_ips
    candidate=$CANDIDATE_FILE
    if ! render_rules "$candidate" 2>/dev/null; then
        rm -f "$candidate"; SYNC_ERROR="룰 파일을 쓸 수 없음($STATE_DIR)"; return 1
    fi
    # 재시작 직후처럼 이미 같은 룰이 적용돼 있으면 reload하지 않는다.
    if (( ! FORCE_APPLY )) && cmp -s "$candidate" "$RULES_FILE"; then
        rm -f "$candidate"; LAST_VERSION=$VERSION; UNCHANGED=1; return 0
    fi

    old_ips=$(rule_ips "$RULES_FILE" | sort)
    new_ips=$(rule_ips "$candidate" | sort)
    if ! apply_rules "$candidate"; then
        # 실패 지점에 따라 nginx가 새 룰을 읽었을 수도 있으므로, 다음 주기에는 같은 목록이어도 다시 적용한다.
        rm -f "$candidate"; FORCE_APPLY=1; SYNC_ERROR=$APPLY_ERROR; return 1
    fi
    # version은 적용이 끝난 뒤에만 기억한다.
    LAST_VERSION=$VERSION
    FORCE_APPLY=0
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
        return 1
    fi
    if ! rm -f "$CANDIDATE_FILE" "$BACKUP_FILE.tmp" "$RESTORE_FILE"; then
        log '오류: 복구용 임시 파일을 정리하지 못했다'
        return 1
    fi
    # 적용 도중 종료됐다면 교체된 룰은 검증·reload 전일 수 있다. 백업(마지막 정상 룰)으로 되돌린다.
    if [[ -e $BACKUP_FILE ]]; then
        if restore_backup; then
            log "적용이 끝나지 않은 룰이 있어 마지막 정상 룰로 되돌렸다"
        else
            log "경고: 마지막 정상 룰($BACKUP_FILE)로 되돌리지 못했다. 볼륨 권한을 확인한다"
            return 1
        fi
        # 미완료 후보를 빈 룰로 대체하지 않는다. 복원된 백업도 유효하지 않으면 시작을 중단한다.
        if [[ ! -s $RULES_FILE ]] || ! rules_file_valid; then
            log '오류: 복원된 마지막 정상 룰의 형식이 올바르지 않다'
            return 1
        fi
        # 여기서는 nginx가 아직 시작되지 않았다. .prev는 run의 검증·reload 확인 후 제거한다.
    fi
    if [[ ! -s $RULES_FILE ]]; then
        printf '%s\n' "$EMPTY_RULES" > "$RULES_FILE" || return 1
        log "저장된 룰이 없어 차단 없이 시작한다"
    elif rules_file_valid; then
        log "마지막 정상 룰로 시작한다: 차단 IP $(rule_ips "$RULES_FILE" | grep -c .)개"
    else
        mv -f "$RULES_FILE" "$RULES_FILE.invalid" || return 1
        printf '%s\n' "$EMPTY_RULES" > "$RULES_FILE" || return 1
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
