#!/usr/bin/env bash
# 백엔드 블랙리스트(GET /internal/waf/blacklist)를 ModSecurity 차단 룰로 바꿔 WAF에 적용하고,
# 적용 결과를 백엔드(POST /internal/waf/sync-status)에 보고한다.
#
#   init-volume  상태 볼륨을 준비한다 (root, waf-blacklist-init 컨테이너에서 실행)
#   prepare      nginx 시작 직전에 저장된 룰을 확인한다 (99-blacklist-sync.sh에서 실행)
#   run          주기 동기화·상태 보고 루프 (99-blacklist-sync.sh가 백그라운드로 실행)
#   once         한 번만 동기화한다 (수동 점검용. 상태 보고는 run 루프가 다음 주기에 한다)
#
# 동기화 흐름: 스냅샷 조회 -> JSON 검증 -> version 비교 -> IP 검증·제외 -> 룰 생성
#              -> 백업 -> 교체 -> nginx -t -> reload 확인 -> 백업 삭제
# 조회·검증·적용 중 하나라도 실패하면 기존 룰을 그대로 둔다(마지막 정상 설정 유지).
# 적용 중에는 백업(blacklist.conf.prev)이 마지막 정상 룰이다. 백업이 남아 있으면 적용이 끝나지 않은
# 것이므로 다음 동기화나 재시작 때 백업으로 되돌린다. 적용에 실패하면 다음 주기에 반드시 다시 적용한다.
# 정상 응답의 빈 목록은 "차단할 IP 없음"으로 보고 기존 차단을 해제한다.
#
# 상태 보고(형식: docs/waf-sync-status-api.md): run 루프가 동기화마다 순서대로 한 번씩 보낸다.
# 룰 파일은 nginx 시작 전(prepare)이나 새 worker까지 확인한 reload로만 바뀐다. 그래서 백업이 없고
# reload 결과 미확인 표시(UNVERIFIED_FLAG)도 없으면, 실행 중인 nginx는 룰 파일대로 동작한다(적용 확인).
# 이때만 룰 파일 머리 주석의 version과 차단 제외 IP를 적용 상태로 보고하고, 아니면 null로 보고한다.
# 보고에 실패해도 차단 설정은 그대로 두고, 쌓아 두지 않고 다음 주기에 최신 상태를 다시 보낸다.
set -uo pipefail
shopt -s nullglob
export LC_ALL=C

STATE_DIR=${WAF_BLACKLIST_STATE_DIR:-/var/lib/waf-blacklist}
RULES_FILE=$STATE_DIR/blacklist.conf   # CUSTOM-003-blacklist-sync.conf가 Include하는 파일
CANDIDATE_FILE=$RULES_FILE.new         # 검증 전 새 룰
BACKUP_FILE=$RULES_FILE.prev           # 적용 중에만 존재하는 마지막 정상 룰
SYNC_URL=${WAF_SYNC_URL:-http://backend:8080/internal/waf/blacklist}
STATUS_URL=${WAF_SYNC_STATUS_URL:-${SYNC_URL%/blacklist}/sync-status}
SYNC_TOKEN=${WAF_SYNC_TOKEN:-}
SYNC_INTERVAL=${WAF_SYNC_INTERVAL:-10}
WAF_ID=${WAF_ID:-local-waf-1}          # 백엔드가 WAF를 구분하는 고정 이름(운영 aws-waf-1)
EXCLUDE_IPS=${WAF_SYNC_EXCLUDE_IPS:-}
NGINX_PID_FILE=${WAF_NGINX_PID_FILE:-/tmp/nginx.pid}
PROC_DIR=${WAF_PROC_DIR:-/proc}
RELOAD_TIMEOUT=${WAF_RELOAD_TIMEOUT:-10}   # reload 후 새 worker를 기다리는 시간(초)
[[ $RELOAD_TIMEOUT =~ ^[1-9][0-9]*$ ]] || RELOAD_TIMEOUT=10
LOCK_DIR=${TMPDIR:-/tmp}
# 있으면 실행 중인 nginx 설정이 룰 파일과 다를 수 있다(reload 결과 미확인). run과 once가 함께 본다.
UNVERIFIED_FLAG=$LOCK_DIR/waf-blacklist-sync.unverified
NGINX_UID=101

# MODSEC_RULE_ENGINE=DetectionOnly에서는 deny가 실행되지 않는다.
# ctl:ruleEngine=On은 이 룰에 걸린 요청에서만 엔진을 켜므로 나머지 CRS 판정은 계속 탐지만 한다.
RULE_PREFIX='SecRule REMOTE_ADDR "@ipMatch '
RULE_SUFFIX="\" \"id:20100,phase:1,deny,status:403,log,msg:'Blacklisted IP (backend sync)',tag:'custom/blacklist',ctl:ruleEngine=On\""
EMPTY_RULES='# 차단할 IP가 없다(동기화 전이거나 블랙리스트가 비어 있음).'
EXCLUDED_COMMENT='# 차단 제외: '   # 뒤에 "<IP> <사유 코드>"

LAST_VERSION=''   # 이 프로세스가 룰을 만들어 적용까지 확인한 version
UNCHANGED=0
ATTEMPTED_VERSION='' APPLIED_VERSION=''
APPLIED_EXCLUDED=()
ERROR_CODE='' SYNC_ERROR='' FETCH_ERROR='' RELOAD_ERROR='' REPORT_ERROR=''
declare -A PROTECTED=()

log() { printf '%s [blacklist-sync] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

# 로그에 남길 때 백엔드가 준 값의 제어 문자 등을 지운다.
printable() { local s=${1//[^0-9A-Za-z.:\/_-]/?}; printf '%s' "${s:0:64}"; }

# 동기화 실패 사유를 남긴다. $1: 보고용 오류 코드, $2: 로그·보고 메시지
fail() { ERROR_CODE=$1; SYNC_ERROR=$2; }

mark_unverified() { : > "$UNVERIFIED_FLAG"; }

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

# 차단하면 모든 요청이나 내부 통신이 막히는 IP와 보고용 제외 사유. 127.0.0.0/8은 exclusion_reason에서 따로 확인한다.
# 한 IP가 여러 사유에 해당하면 나중에 넣는 사유가 남는다: 고정 주소 > 신뢰 프록시 > 게이트웨이 > 설정.
load_protected() {
    local ip gateway
    local -a items=()
    IFS=', ' read -ra items <<< "$EXCLUDE_IPS"
    for ip in "${items[@]}"; do
        ip=${ip,,}
        if is_ip "$ip"; then
            PROTECTED[$ip]=CONFIGURED_EXCLUSION
        else
            log "경고: WAF_SYNC_EXCLUDE_IPS의 '$(printable "$ip")'는 단일 IP가 아니어서 무시한다"
        fi
    done
    if gateway=$(default_gateway); then PROTECTED[$gateway]=GATEWAY; fi
    # 신뢰 프록시(SET_REAL_IP_FROM)가 단일 IP면 함께 제외한다. CIDR이면 WAF_SYNC_EXCLUDE_IPS로 지정한다.
    ip=${SET_REAL_IP_FROM:-}
    ip=${ip,,}
    if is_ip "$ip"; then PROTECTED[$ip]=TRUSTED_PROXY; fi
    PROTECTED[0.0.0.0]=UNSPECIFIED_ADDRESS
    PROTECTED[::]=UNSPECIFIED_ADDRESS
    PROTECTED[::1]=LOOPBACK
}

# 차단하면 안 되는 IP면 REASON에 제외 사유를 넣고 성공한다.
exclusion_reason() {
    REASON=''
    if [[ $1 == 127.* ]]; then
        REASON=LOOPBACK
    elif [[ -n ${PROTECTED[$1]+x} ]]; then
        REASON=${PROTECTED[$1]}
    fi
    [[ -n $REASON ]]
}

protected_summary() {
    local ip out='127.0.0.0/8(LOOPBACK)'
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
# 차단하면 안 되는 IP는 백엔드가 준 문자열 그대로 "<IP> <사유>"로 EXCLUDED에 남긴다(보고용).
select_ips() {
    local raw ip
    local -A seen=() seen_excluded=()
    local -a invalid=() skipped=()
    BLOCK_IPS=() EXCLUDED=()
    for raw in "${RAW_IPS[@]}"; do
        ip=${raw,,}
        if ! is_ip "$ip"; then invalid+=("$(printable "$raw")"); continue; fi
        if exclusion_reason "$ip"; then
            if [[ -z ${seen_excluded[$raw]+x} ]]; then
                seen_excluded[$raw]=1
                EXCLUDED+=("$raw $REASON")
                skipped+=("$raw($REASON)")
            fi
            continue
        fi
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
    local joined item
    {
        printf '# 자동 생성: waf/sync/blacklist-sync.sh (백엔드 version %s). 직접 수정하지 않는다.\n' "$VERSION"
        for item in "${EXCLUDED[@]}"; do printf '%s%s\n' "$EXCLUDED_COMMENT" "$item"; done
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

# 룰 파일 머리 주석의 백엔드 version과 차단 제외 IP("<IP> <사유>")를 FILE_VERSION, FILE_EXCLUDED에 넣는다.
read_rules_meta() {
    local line re_version='\(백엔드 version ([0-9a-f]{64})\)' re_excluded="^$EXCLUDED_COMMENT([0-9A-Fa-f.:]+ [A-Z_]+)\$"
    FILE_VERSION='' FILE_EXCLUDED=()
    [[ -r $1 ]] || return 0
    while IFS= read -r line || [[ -n $line ]]; do
        [[ $line == '#'* ]] || continue
        if [[ $line =~ $re_version ]]; then
            FILE_VERSION=${BASH_REMATCH[1]}
        elif [[ $line =~ $re_excluded ]]; then
            FILE_EXCLUDED+=("${BASH_REMATCH[1]}")
        fi
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
# 0: 확인 완료, 1: 신호를 보내지 않음·전송 실패(기존 설정 유지), 2: 신호는 보냈지만 시간 안에 확인 못 함(적용 여부 모름)
reload_nginx() {
    local before after output i
    before=$(worker_pids | sort)
    # worker를 볼 수 없으면 적용을 확인할 수 없으므로 신호를 보내지 않는다.
    if [[ -z $before ]]; then RELOAD_ERROR='nginx worker를 찾지 못해 적용을 확인할 수 없음'; return 1; fi
    if ! output=$(nginx -s reload 2>&1); then
        RELOAD_ERROR=$(grep -m1 -oE '\[(emerg|alert|error)\].*' <<< "$output" | cut -c1-200)
        return 1
    fi
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

# 백업이 있으면 RULES_FILE로 되돌린다. 0: 되돌림 또는 백업 없음, 1: 되돌리지 못함(백업은 그대로 남는다)
restore_backup() {
    [[ -e $BACKUP_FILE ]] || return 0
    mv -f "$BACKUP_FILE" "$RULES_FILE"
}

# reload 실패 뒤 이전 룰로 되돌린다. $1: reload_nginx 결과
# 신호를 보낸 뒤 확인만 시간 초과됐다면(2) 새 룰이 이미 적용됐거나 적용 중일 수 있으므로,
# 파일만 되돌리지 않고 이전 룰로 다시 검증·reload·확인해 실제 nginx 설정을 파일과 맞춘다.
# 맞추지 못하면 UNVERIFIED_FLAG를 남겨 적용 상태를 모른다고 보고하고 다음 주기에 다시 적용한다.
rollback_reload() {
    local output
    if ! restore_backup; then SYNC_ERROR+=', 이전 룰 복구 실패'; return 1; fi
    (( $1 == 2 )) || return 0
    if ! output=$(nginx -t 2>&1) || ! reload_nginx; then
        mark_unverified
        SYNC_ERROR+=', 이전 룰 재적용도 실패(실제 적용 상태 확인 필요)'
        return 1
    fi
    rm -f "$UNVERIFIED_FLAG"
    SYNC_ERROR+=', 이전 룰로 다시 reload함'
}

# $1(RULES_FILE과 같은 디렉터리의 새 룰)을 검증 후 교체한다. 실패하면 이전 룰로 되돌린다.
# 교체부터 완료까지는 BACKUP_FILE이 마지막 정상 룰이며, 적용이 끝나거나 되돌린 뒤에만 사라진다.
# 0: 적용 완료, 1: 실패(ERROR_CODE·SYNC_ERROR)
apply_rules() {
    local candidate=$1 output rc code
    if ! save_backup; then fail STATE_WRITE_FAILED '이전 룰 백업 실패'; return 1; fi
    if ! mv -f "$candidate" "$RULES_FILE"; then
        # rename은 원자적이라 실패하면 RULES_FILE은 그대로다. 백업만 지운다.
        rm -f "$BACKUP_FILE"
        fail STATE_WRITE_FAILED '룰 파일 교체 실패'
        return 1
    fi
    if ! output=$(nginx -t 2>&1); then
        fail NGINX_TEST_FAILED "nginx -t 실패: $(grep -m1 -oE '\[emerg\].*' <<< "$output" | cut -c1-200)"
        restore_backup || SYNC_ERROR+=', 이전 룰 복구 실패'
        return 1
    fi
    # nginx가 아직 뜨지 않았으면 파일만 바꿔 두고, nginx가 시작할 때 읽게 한다.
    if nginx_running; then
        reload_nginx
        rc=$?
        if (( rc != 0 )); then
            if (( rc == 2 )); then code=RELOAD_TIMEOUT; else code=RELOAD_FAILED; fi
            fail "$code" "reload 실패: $RELOAD_ERROR"
            rollback_reload "$rc"
            return 1
        fi
    fi
    # 이제 nginx는 룰 파일대로 동작한다.
    rm -f "$UNVERIFIED_FLAG"
    # 백업이 남으면 재시작 때 이전 룰로 되돌아가므로 지우지 못하면 실패로 본다.
    if ! rm -f "$BACKUP_FILE"; then fail STATE_WRITE_FAILED '적용 후 백업 삭제 실패'; return 1; fi
}

# 추가·해제된 IP를 로그 한 줄로 요약한다(많으면 앞의 10개만). $1, $2: 정렬된 IP 목록
summarize_change() {
    local added removed
    added=$(comm -13 <(printf '%s\n' "$1" | sed '/^$/d') <(printf '%s\n' "$2" | sed '/^$/d') | head -10 | paste -sd, -)
    removed=$(comm -23 <(printf '%s\n' "$1" | sed '/^$/d') <(printf '%s\n' "$2" | sed '/^$/d') | head -10 | paste -sd, -)
    printf '추가 [%s] 해제 [%s]' "${added:-없음}" "${removed:-없음}"
}

# 0: 적용 완료 또는 변경 없음, 1: 실패(ERROR_CODE·SYNC_ERROR, 기존 룰 유지)
sync_once() {
    local response candidate old_ips new_ips
    ATTEMPTED_VERSION=''
    # 이전 적용이 끝나지 않았다면(중단·복구 실패) 백업이 마지막 정상 룰이다. 덮어쓰기 전에 먼저 되돌린다.
    # 중단 시점에 따라 nginx가 교체된 룰을 이미 읽었을 수 있으므로 같은 목록이어도 다시 적용한다.
    if [[ -e $BACKUP_FILE ]]; then
        if ! restore_backup; then fail STATE_WRITE_FAILED '끝나지 않은 이전 적용을 되돌리지 못함'; return 1; fi
        mark_unverified
        log "끝나지 않은 이전 적용을 마지막 정상 룰로 되돌렸다. 최신 목록으로 다시 적용한다"
    fi
    response=$(mktemp) || { fail STATE_WRITE_FAILED '임시 파일 생성 실패'; return 1; }
    if ! fetch_snapshot "$response"; then
        rm -f "$response"; fail SNAPSHOT_FETCH_FAILED "목록 조회 실패: $FETCH_ERROR"; return 1
    fi
    if ! parse_snapshot "$response"; then
        rm -f "$response"; fail SNAPSHOT_INVALID '응답 형식이 올바르지 않음'; return 1
    fi
    rm -f "$response"
    ATTEMPTED_VERSION=$VERSION

    # 이미 확인한 version이고 룰 파일도 그대로면(once 등이 바꾸지 않았으면) 룰을 다시 만들지 않는다.
    read_rules_meta "$RULES_FILE"
    if [[ ! -e $UNVERIFIED_FLAG && $VERSION == "$LAST_VERSION" && $FILE_VERSION == "$VERSION" ]]; then
        UNCHANGED=1; return 0
    fi

    select_ips
    candidate=$CANDIDATE_FILE
    if ! render_rules "$candidate" 2>/dev/null; then
        rm -f "$candidate"; fail STATE_WRITE_FAILED "룰 파일을 쓸 수 없음($STATE_DIR)"; return 1
    fi
    # 재시작 직후처럼 이미 같은 룰이 적용돼 있으면 reload하지 않는다.
    if [[ ! -e $UNVERIFIED_FLAG ]] && cmp -s "$candidate" "$RULES_FILE"; then
        rm -f "$candidate"; LAST_VERSION=$VERSION; UNCHANGED=1; return 0
    fi

    old_ips=$(rule_ips "$RULES_FILE" | sort)
    new_ips=$(rule_ips "$candidate" | sort)
    if ! apply_rules "$candidate"; then
        # 실패한 목록의 version은 기억하지 않으므로 다음 주기에 다시 적용한다.
        rm -f "$candidate"; return 1
    fi
    # version은 적용이 끝난 뒤에만 기억한다.
    LAST_VERSION=$VERSION
    UNCHANGED=0
    log "적용 완료: 차단 IP ${#BLOCK_IPS[@]}개, $(summarize_change "$old_ips" "$new_ips")"
}

# 실행 중인 nginx에 적용이 확인된 룰의 version과 차단 제외 IP를 APPLIED_VERSION, APPLIED_EXCLUDED에 넣는다.
# 적용 중(백업 있음)이거나 reload 결과를 확인하지 못했거나 nginx가 없으면 모르는 것('')으로 둔다.
load_applied_state() {
    APPLIED_VERSION='' APPLIED_EXCLUDED=()
    [[ -e $BACKUP_FILE || -e $UNVERIFIED_FLAG ]] && return 0
    nginx_running || return 0
    read_rules_meta "$RULES_FILE"
    APPLIED_VERSION=$FILE_VERSION
    APPLIED_EXCLUDED=("${FILE_EXCLUDED[@]}")
}

# 같은 컨테이너에서 run과 once가 동시에 파일을 바꾸지 않도록 동기화 한 번마다 잠근다.
# 보고할 적용 상태도 잠근 채로 읽는다.
locked_sync() {
    local rc
    if ! flock -w 30 8; then
        fail LOCK_TIMEOUT '다른 동기화가 끝나지 않음'
        ATTEMPTED_VERSION='' APPLIED_VERSION='' APPLIED_EXCLUDED=()
        return 1
    fi
    sync_once
    rc=$?
    load_applied_state
    flock -u 8
    return "$rc"
}

# ---------------------------------------------------------------- 상태 보고

# 동기화 결과($1: locked_sync 종료 코드)를 보고 본문(JSON)으로 출력한다.
#   SUCCESS  시도한 version의 적용을 확인함
#   FAILURE  동기화 실패. 적용 version은 기존 룰 유지·복구를 확인했을 때만 보낸다
#   UNKNOWN  실패는 없지만 적용을 확인하지 못함(nginx 미실행 등)
# 적용 상태를 모르면 appliedVersion과 excludedIps를 null로 보낸다(이전 성공 값을 보내지 않는다).
status_json() {
    local result applied=$APPLIED_VERSION code='' message=''
    if (( $1 != 0 )); then
        result=FAILURE code=$ERROR_CODE message=$SYNC_ERROR
    elif [[ -n $applied && $applied == "$ATTEMPTED_VERSION" ]]; then
        result=SUCCESS
    else
        result=UNKNOWN applied=''
    fi
    perl -MJSON::PP -MEncode -e '
        my ($id, $attempted, $applied, $result, $code, $message, @excluded) =
            map { Encode::decode("UTF-8", $_) } @ARGV;
        my $or_null = sub { length $_[0] ? $_[0] : undef };
        print JSON::PP->new->utf8->canonical->encode({
            wafId => $id,
            attemptedVersion => $or_null->($attempted),
            appliedVersion => $or_null->($applied),
            lastSyncResult => $result,
            excludedIps => length $applied
                ? [map { my ($ip, $reason) = split / /; +{ip => $ip, reason => $reason} } @excluded]
                : undef,
            error => length $code ? {code => $code, message => substr($message, 0, 300)} : undef,
        });
    ' -- "$WAF_ID" "$ATTEMPTED_VERSION" "$applied" "$result" "$code" "$message" "${APPLIED_EXCLUDED[@]}"
}

# 상태를 보고한다. 실패 이유는 REPORT_ERROR에 남긴다. $1: locked_sync 종료 코드
send_report() {
    local body header code rc
    body=$(mktemp) || { REPORT_ERROR='임시 파일 생성 실패'; return 1; }
    if ! status_json "$1" > "$body"; then rm -f "$body"; REPORT_ERROR='보고 본문 생성 실패'; return 1; fi
    header=$(mktemp) || { rm -f "$body"; REPORT_ERROR='임시 파일 생성 실패'; return 1; }
    # 토큰이 프로세스 인자에 보이지 않도록 헤더를 파일로 넘긴다.
    printf 'X-WAF-Sync-Token: %s\nContent-Type: application/json\n' "$SYNC_TOKEN" > "$header"
    code=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 5 \
        -H "@$header" --data-binary "@$body" "$STATUS_URL")
    rc=$?
    rm -f "$body" "$header"
    if (( rc == 28 )); then REPORT_ERROR='응답 시간 초과(5초)'; return 1; fi
    if (( rc != 0 )); then REPORT_ERROR="연결 실패(curl 종료 코드 $rc)"; return 1; fi
    # 백엔드는 DB 저장을 마친 뒤에만 204를 준다.
    if [[ $code != 204 ]]; then REPORT_ERROR="HTTP $code"; return 1; fi
}

# ---------------------------------------------------------------- 실행 모드

init_volume() {
    mkdir -p "$STATE_DIR"
    [[ -s $RULES_FILE ]] || printf '%s\n' "$EMPTY_RULES" > "$RULES_FILE"
    chown -R "$NGINX_UID:$NGINX_UID" "$STATE_DIR"
    log "상태 볼륨 준비 완료: $STATE_DIR"
}

prepare() {
    # nginx가 새로 시작하며 룰 파일을 읽으므로 이전 실행의 reload 미확인 표시는 필요 없다.
    rm -f "$UNVERIFIED_FLAG"
    if [[ ! -w $STATE_DIR ]]; then
        log "경고: $STATE_DIR에 쓸 수 없다. waf-blacklist-init 실행 여부와 볼륨 권한을 확인한다"
        return 0
    fi
    rm -f "$CANDIDATE_FILE" "$BACKUP_FILE.tmp"
    # 적용 도중 종료됐다면 교체된 룰은 검증·reload 전일 수 있다. 백업(마지막 정상 룰)으로 되돌린다.
    if [[ -e $BACKUP_FILE ]]; then
        if restore_backup; then
            log "적용이 끝나지 않은 룰이 있어 마지막 정상 룰로 되돌렸다"
        else
            log "경고: 마지막 정상 룰($BACKUP_FILE)로 되돌리지 못했다. 볼륨 권한을 확인한다"
        fi
    fi
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
    local last_error='' failures=0 last_report_error='' report=1 rc
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
    if [[ ! $WAF_ID =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]]; then
        log "경고: WAF_ID '$(printable "$WAF_ID")'가 올바르지 않아 상태를 보고하지 않는다(소문자·숫자·.·_·-, 64자 이하)"
        report=0
    fi
    load_protected
    log "동기화 시작: $SYNC_URL, ${SYNC_INTERVAL}초 간격, 차단 제외: $(protected_summary)"
    (( report )) && log "상태 보고: $STATUS_URL (wafId $WAF_ID)"
    # 훅은 nginx 시작 전에 실행되므로 reload를 확인할 수 있을 때까지(worker가 뜰 때까지) 최대 60초 기다린다.
    for _ in {1..60}; do nginx_running && [[ -n $(worker_pids) ]] && break; sleep 1; done

    while true; do
        locked_sync
        rc=$?
        if (( rc == 0 )); then
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
        if (( report )); then
            if send_report "$rc"; then
                if [[ -n $last_report_error ]]; then log "상태 보고 복구"; last_report_error=''; fi
            elif [[ $REPORT_ERROR != "$last_report_error" ]]; then
                log "상태 보고 실패, 차단 설정은 그대로 두고 다음 주기에 최신 상태를 보고한다: $REPORT_ERROR"
                last_report_error=$REPORT_ERROR
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
