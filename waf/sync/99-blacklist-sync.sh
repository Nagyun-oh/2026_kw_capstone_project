#!/bin/sh
# /docker-entrypoint.d 훅: nginx 시작 직전에 저장된 블랙리스트 룰을 확인하고 동기화 루프를 띄운다.
# 이미지 entrypoint는 실행 권한이 있는 *.sh만 실행하므로 이 파일은 755로 유지한다.
# 저장된 룰을 안전하게 준비하지 못하면 미완료 후보로 nginx가 시작되지 않도록 오류를 전파한다.
SCRIPT=/opt/waf-blacklist/blacklist-sync.sh

if ! bash "$SCRIPT" prepare; then
    echo '[blacklist-sync] 저장된 룰 준비 실패: WAF 시작을 중단한다' >&2
    exit 1
fi
setsid bash "$SCRIPT" run </dev/null &
exit 0
