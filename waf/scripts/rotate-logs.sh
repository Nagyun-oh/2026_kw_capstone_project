#!/usr/bin/env bash
# 실행 중인 access/error 로그만 교체한다. 보관 로그는 삭제·압축하지 않는다.
set -euo pipefail

mode=${1:-rotate}
if [[ $# -gt 1 || ( "$mode" != rotate && "$mode" != --dry-run ) ]]; then
    echo "Usage: $0 [--dry-run]" >&2
    exit 2
fi

for container in waf waf-fluent-bit; do
    if [[ $(docker inspect --format '{{.State.Running}}' "$container") != true ]]; then
        echo "$container is not running; rotation skipped." >&2
        exit 1
    fi
done

# Docker 소켓을 다른 컨테이너에 마운트하지 않고 호스트에서 실행한다.
docker exec -i --user 0 waf sh -s -- "$mode" <<'SH'
set -eu
mode=$1
log_dir=/var/log/nginx
pid_file=/tmp/nginx.pid
test -r "$pid_file"
kill -0 "$(cat "$pid_file")"

if [ "$mode" = --dry-run ]; then
    for name in access.log error.log; do
        if [ -s "$log_dir/$name" ]; then
            echo "Would archive $log_dir/$name and reopen Nginx logs."
        fi
    done
    echo 'No log files changed. No deletion or compression is configured.'
    exit 0
fi

# 동시에 실행된 교체 작업을 차단한다. 강제 종료 시 잠금이 남으면 수동 확인한다.
lock=/tmp/waf-log-rotation.lock
if ! mkdir "$lock"; then
    echo 'Rotation lock exists; inspect the previous rotation before retrying.' >&2
    exit 1
fi
trap 'rmdir "$lock"' EXIT
trap 'exit 1' HUP INT TERM

archive="$log_dir/archive/$(date -u +%Y%m%dT%H%M%SZ)-$$"
moved=''
for name in access.log error.log; do
    # 빈 파일이나 끊어진 링크도 포함해 이동 전에 모두 검사한다.
    if [ -L "$log_dir/$name" ] || { [ -e "$log_dir/$name" ] && [ ! -f "$log_dir/$name" ]; }; then
        echo "Refusing non-regular log file: $log_dir/$name" >&2
        exit 1
    fi
done
for name in access.log error.log; do
    if [ -s "$log_dir/$name" ]; then
        if [ -z "$moved" ]; then
            mkdir -p "$log_dir/archive"
            mkdir "$archive"
        fi
        mv "$log_dir/$name" "$archive/$name"
        moved="$moved $name"
    fi
done

if [ -z "$moved" ]; then
    echo 'No non-empty log files to rotate.'
    exit 0
fi

# rename 후 USR1 방식으로 reopen. copytruncate나 원본 내용 삭제는 하지 않는다.
nginx -s reopen
for name in $moved; do
    attempt=0
    until [ -f "$log_dir/$name" ]; do
        attempt=$((attempt + 1))
        if [ "$attempt" -ge 10 ]; then
            echo "Log reopen not confirmed: $name. Preserved logs: $archive" >&2
            exit 1
        fi
        sleep 1
    done
done
echo "Logs preserved in $archive; Nginx log files reopened."
SH
