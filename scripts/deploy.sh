#!/usr/bin/env bash
# EC2에서 ECR 이미지로 앱 서비스(backend/frontend/ai)를 교체하고 상태를 확인한다.
#
# GitHub Actions(deploy.yml)가 SSM Run Command로 git checkout 후 root 권한으로 실행한다.
# 롤백이나 수동 재배포도 같은 방식으로 실행할 수 있다.
#
# 사용법 (저장소 루트에서):
#   sudo ECR_REGISTRY=<계정>.dkr.ecr.ap-northeast-2.amazonaws.com bash scripts/deploy.sh <git-sha>
#
# 전제:
#   - EC2 Instance Role에 ECR pull 권한이 있고 AWS CLI가 설치돼 있다.
#   - .env.aws(비밀값)가 저장소 루트에 있다. 이 스크립트는 IMAGE_* 두 줄만 갱신한다.
set -euo pipefail

IMAGE_TAG="${1:?usage: deploy.sh <git-sha>}"
: "${ECR_REGISTRY:?ECR_REGISTRY is required}"
AWS_REGION="${AWS_REGION:-ap-northeast-2}"

# SSM 셸에는 snap 경로가 PATH에 없을 수 있다.
export PATH="$PATH:/snap/bin:/usr/local/bin"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$REPO_DIR/.env.aws"
APP_SERVICES=(backend frontend ai)
HEALTH_TIMEOUT_SEC=300

cd "$REPO_DIR"
log() { echo "[deploy] $*"; }

if [[ ! "$IMAGE_TAG" =~ ^[0-9a-f]{40}$ ]]; then
  echo "[deploy] invalid git sha: $IMAGE_TAG" >&2
  exit 1
fi
if [[ ! -f "$ENV_FILE" ]]; then
  echo "[deploy] $ENV_FILE not found (docs/06 4장 참고)" >&2
  exit 1
fi

# 이번 배포의 이미지 이름. 셸 환경변수가 --env-file 값보다 우선한다.
export IMAGE_REGISTRY_PREFIX="${ECR_REGISTRY}/"
export IMAGE_TAG

# 컨테이너 교체 후 .env.aws의 IMAGE_* 값만 갱신해, 이후 수동 compose 명령도 현재 배포된 이미지를 쓰게 한다.
# cat으로 덮어써서 파일 소유자(ubuntu)와 권한(600)을 유지한다.
set_env() {
  local key="$1" value="$2" tmp
  tmp="$(mktemp)"
  grep -v "^${key}=" "$ENV_FILE" > "$tmp" || true
  echo "${key}=${value}" >> "$tmp"
  cat "$tmp" > "$ENV_FILE"
  rm -f "$tmp"
}

compose() { docker compose --env-file "$ENV_FILE" -f compose.aws.yaml "$@"; }

# root로 실행되므로 읽기 전용 git 명령에만 safe.directory를 지정한다. (git 쓰기 작업은 ubuntu 계정으로 수행)
log "commit: $(git -c safe.directory="$REPO_DIR" log -1 --format='%h %s')"
log "ECR login"
aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "$ECR_REGISTRY" >/dev/null

log "pull images (tag ${IMAGE_TAG:0:12})"
compose pull --quiet "${APP_SERVICES[@]}"

log "start services"
# EC2에서는 빌드하지 않는다. 인프라 서비스는 설정 변경이 없으면 그대로 유지된다.
compose up -d --no-build --remove-orphans
set_env IMAGE_REGISTRY_PREFIX "$IMAGE_REGISTRY_PREFIX"
set_env IMAGE_TAG "$IMAGE_TAG"

log "wait for health (max ${HEALTH_TIMEOUT_SEC}s)"
deadline=$((SECONDS + HEALTH_TIMEOUT_SEC))
backend_ok=false ai_ok=false frontend_ok=false
while (( SECONDS < deadline )); do
  curl -fsS -m 5 http://127.0.0.1:8080/actuator/health 2>/dev/null | grep -q '"UP"' && backend_ok=true
  curl -fsS -m 5 http://127.0.0.1:8000/health 2>/dev/null | grep -q '"model_loaded":true' && ai_ok=true
  curl -fsS -m 5 -o /dev/null http://127.0.0.1:3000/ 2>/dev/null && frontend_ok=true
  if $backend_ok && $ai_ok && $frontend_ok; then break; fi
  sleep 5
done

compose ps --format 'table {{.Service}}\t{{.Status}}'
log "backend=$backend_ok ai=$ai_ok frontend=$frontend_ok"

if ! ($backend_ok && $ai_ok && $frontend_ok); then
  log "health check failed. recent logs:"
  compose logs --tail 40 "${APP_SERVICES[@]}" || true
  exit 1
fi

# 이전 배포의 앱 이미지를 정리해 디스크를 확보한다. 롤백 시에는 ECR에서 다시 받는다.
docker images --format '{{.Repository}}:{{.Tag}}' \
  | grep "^${ECR_REGISTRY}/security-" \
  | grep -v ":${IMAGE_TAG}$" \
  | xargs -r docker rmi >/dev/null 2>&1 || true
docker image prune -f >/dev/null
log "done: ${IMAGE_TAG:0:12}"
