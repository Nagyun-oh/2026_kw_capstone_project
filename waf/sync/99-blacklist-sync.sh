#!/bin/sh
# /docker-entrypoint.d 훅: nginx 시작 직전에 저장된 블랙리스트 룰을 확인하고 동기화 루프를 띄운다.
# 이미지 entrypoint는 실행 권한이 있는 *.sh만 실행하므로 이 파일은 755로 유지한다.
# 이 훅이 실패해도 WAF는 저장된 룰(없으면 빈 룰)로 시작해야 하므로 항상 0으로 끝낸다.
SCRIPT=/opt/waf-blacklist/blacklist-sync.sh

bash "$SCRIPT" prepare || true
setsid bash "$SCRIPT" run </dev/null &
exit 0
