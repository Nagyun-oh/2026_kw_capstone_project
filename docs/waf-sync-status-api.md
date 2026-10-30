# WAF 동기화 상태 보고 API (합의 초안)

> **상태**: 보안(WAF)·백엔드 합의용 초안. WAF 쪽 보고 전송은 이 문서대로 구현했다([waf/sync/blacklist-sync.sh](../waf/sync/blacklist-sync.sh)).
> 백엔드 수신 API·저장·조회와 대시보드 표시는 아직 없다. 이번 보완에서 `INVALID_FORMAT` 보고와 #92의 안전한 복구를 WAF에 반영했다. [11. 변경 제안](#11-변경-제안-합의-필요)의 백엔드 항목은 후속 작업이다.

## 1. 목적과 범위

EC2의 WAF 한 대를 기준으로, **블랙리스트 전체의 동기화 상태**를 대시보드에 표시한다.

| 대시보드에서 확인할 것 | 근거 필드 |
| --- | --- |
| 현재 DB 목록이 WAF에 반영됐는지 | `appliedVersion`과 현재 DB 스냅샷 version 비교 |
| 마지막 동기화가 실패했는지 | `lastSyncResult`, `error` |
| WAF의 상태 보고가 끊겼는지 | 백엔드가 기록한 마지막 수신 시각 |
| 차단에서 제외된 IP가 있는지 | `excludedIps` |

**'적용 확인'은 WAF 설정 반영을 확인했다는 뜻이다.** 실제 HTTP 요청이 403으로 차단되는지는 통합 검증에서 따로 확인한다.

## 2. 흐름

변경 전에는 동기화 결과가 WAF 컨테이너 로그(`docker logs waf`)에만 남아 대시보드에서 볼 수 없었다.

```text
변경 전
  백엔드 GET /internal/waf/blacklist -> WAF 검증·reload·적용 확인 -> (결과는 WAF 로그에만)

변경 후
  백엔드 GET /internal/waf/blacklist          차단 목록과 version 제공
  WAF   검증 -> reload -> 적용 확인
  WAF   POST /internal/waf/sync-status       적용 결과·주기 상태 보고
  백엔드 인증 -> DB 저장 -> 204               수신 시각은 백엔드가 기록
  프론트 관리자 조회 API로 동기화 상태 표시     화면 상태는 백엔드가 계산
```

| 담당 | 범위 |
| --- | --- |
| WAF(보안) | 적용 결과와 주기 상태 보고, 보고 실패 처리, WAF 테스트 |
| 백엔드 | 보고 수신 API, 인증, DB 저장, 관리자 조회 API, 화면 상태 계산 |
| 프론트 | 동기화 상태 표시 |

## 3. API

```http
POST /internal/waf/sync-status
X-WAF-Sync-Token: <기존 동기화 토큰(WAF_SYNC_TOKEN)>
Content-Type: application/json
```

- 스냅샷 조회(`GET /internal/waf/blacklist`)와 **같은 토큰**을 쓴다.
- 일반 관리자 세션으로는 호출할 수 없다(`/internal/waf/**`는 세션을 쓰지 않는 별도 보안 체인).
- WAF 기본 주소는 `WAF_SYNC_URL`의 `/blacklist`를 `/sync-status`로 바꾼 값이다. 다르면 `WAF_SYNC_STATUS_URL`로 지정한다.

| 응답 | 의미 | WAF 동작 |
| --- | --- | --- |
| `204 No Content` | **DB 저장 완료 후** 응답 | 성공 |
| `400` | 본문 형식·일관성 규칙 위반 | 실패로 기록, 다음 주기에 최신 상태 보고 |
| `401` | 토큰 없음·불일치 | 위와 같음 |
| `403` | 경로·권한·CSRF 거부 | 위와 같음 |
| 그 외, 연결 실패, 시간 초과 | 백엔드 문제 | 위와 같음 |

WAF는 `204`만 성공으로 본다. 어떤 실패도 차단 설정에는 영향을 주지 않는다.

## 4. 요청 본문

| 필드 | 타입 | 설명 |
| --- | --- | --- |
| `wafId` | 문자열 | 재시작해도 유지되는 고정 식별값. 운영 `aws-waf-1`, 로컬 `local-waf-1`(`WAF_ID`) |
| `attemptedVersion` | 문자열 또는 `null` | 이번 동기화에서 적용하려 한 스냅샷 version. 목록을 받지 못했거나 응답이 깨져 version을 모르면 `null` |
| `appliedVersion` | 문자열 또는 `null` | **실제 적용을 확인한** version. 확인하지 못했으면 `null` |
| `lastSyncResult` | `SUCCESS` / `FAILURE` / `UNKNOWN` | 목록 동기화 결과. 상태 보고 요청의 성공 여부와는 관계없다 |
| `excludedIps` | 배열 또는 `null` | 적용 확인된 목록 기준으로 차단에서 제외한 IP. 적용 상태를 모르면 `null`, 제외 없음은 `[]` |
| `excludedIps[].ip` | 문자열 | 백엔드 스냅샷에 들어 있던 문자열 그대로 |
| `excludedIps[].reason` | 문자열 | 아래 제외 사유 코드 |
| `error` | 객체 또는 `null` | `{"code": "...", "message": "..."}`. 정상은 `null` |

version 형식은 백엔드 `BlacklistSnapshotService`와 같은 **소문자 SHA-256 64자리**다.

### 제외 사유

| 코드 | 대상 |
| --- | --- |
| `LOOPBACK` | `127.0.0.0/8`, `::1` |
| `UNSPECIFIED_ADDRESS` | `0.0.0.0`, `::` |
| `GATEWAY` | WAF 컨테이너 기본 게이트웨이(로컬은 호스트에서 온 모든 요청, AWS는 호스트 Nginx의 출발지) |
| `TRUSTED_PROXY` | `SET_REAL_IP_FROM`이 단일 IP일 때 그 값(AWS `WAF_TRUSTED_PROXY`) |
| `CONFIGURED_EXCLUSION` | `WAF_SYNC_EXCLUDE_IPS`로 지정한 IP |
| `INVALID_FORMAT` | WAF가 지원하지 않는 문자열(앞자리 0, CIDR, IPv4 포함 IPv6 등). 원래 문자열을 그대로 보고 |

형식 오류로 제외된 값도 누락 없이 보고한다. `excludedIps[].ip`는 올바른 IP라는 보장이 없는 원본 문자열이므로, 백엔드가 일반 IP 검증으로 이 보고를 거부하면 안 된다. 빈 문자열도 `INVALID_FORMAT`으로 전달될 수 있다. 화면에서는 문자열로 안전하게 렌더링한다.

한 IP가 여러 사유에 해당하면 `LOOPBACK`·`UNSPECIFIED_ADDRESS` > `TRUSTED_PROXY` > `GATEWAY` > `CONFIGURED_EXCLUSION` 순으로 하나만 보낸다(AWS에서 게이트웨이와 신뢰 프록시가 같은 IP면 `TRUSTED_PROXY`).

### 오류 코드 (WAF 구현 기준)

초안에는 `RELOAD_TIMEOUT` 예시만 있어 WAF가 보내는 코드를 아래처럼 정했다. 목록 확정은 [변경 제안](#11-변경-제안-합의-필요) 4번이다.

| 코드 | 상황 |
| --- | --- |
| `SNAPSHOT_FETCH_FAILED` | 스냅샷 조회 연결 실패, 200이 아닌 응답 |
| `SNAPSHOT_INVALID` | 응답 JSON 문법·필드·타입 오류 |
| `STATE_WRITE_FAILED` | 룰 파일 생성·백업·교체·복구 실패 |
| `NGINX_TEST_FAILED` | `nginx -t` 실패 |
| `RELOAD_FAILED` | reload 신호를 보내지 못함(nginx는 기존 설정 유지) |
| `RELOAD_TIMEOUT` | reload 신호 후 새 worker 확인 시간 초과 |
| `LOCK_TIMEOUT` | 수동 동기화(`once`)가 끝나지 않아 이번 주기를 건너뜀 |

`message`는 사람이 읽는 한국어 설명이다(최대 300자). 토큰은 넣지 않는다.

## 5. 일관성 규칙

| 결과 | 규칙 |
| --- | --- |
| `SUCCESS` | `attemptedVersion`과 `appliedVersion`이 모두 있고 같다. `excludedIps`는 배열, `error`는 `null` |
| `FAILURE` | `error`가 있다. `appliedVersion`은 실제 유지·복구를 확인한 경우에만 기록한다 |
| `UNKNOWN` | `appliedVersion`과 `excludedIps`는 `null` |

- 실제 적용 상태가 불명확하면 이전 성공 값을 그대로 보내지 않는다.
- `appliedVersion`이 `null`이면 `excludedIps`도 `null`이다. `appliedVersion`이 있으면 `excludedIps`는 배열이다.
- 보고는 순차 전송한다. 실패한 보고를 쌓아 재전송하지 않고 **다음 주기에 최신 상태를 다시 보고**한다.

## 6. 실패했을 때의 보고 기준

기존 목록 A를 쓰다가 새 목록 B 적용에 실패한 경우다.

| 상황 | `attemptedVersion` | `appliedVersion` | `lastSyncResult` |
| --- | --- | --- | --- |
| B 적용 완료 확인 | B | B | `SUCCESS` |
| B 실패 후 A 유지·복구 확인 | B | A | `FAILURE` |
| reload 시간 초과 등으로 실제 적용 상태 불명확 | B | `null` | `FAILURE` |
| 시작 직후 아직 적용 상태를 확인하지 못함(nginx 미실행 등) | 받은 version | `null` | `UNKNOWN` |
| 목록 조회 자체가 실패해 대상 version을 모름 | `null` | 확인된 A 또는 `null` | `FAILURE` |

**파일이 존재하거나 reload 명령이 종료됐다는 이유만으로 성공 보고를 하지 않는다.** WAF 구현에서 각 실패가 어디에 해당하는지는 다음과 같다.

| WAF에서 일어난 일 | 실제 nginx | 보고 |
| --- | --- | --- |
| 조회 실패(연결·HTTP 오류), 응답 형식 오류 | 건드리지 않음 | `attemptedVersion = null`, `appliedVersion` = 마지막 확인 version |
| 룰 파일 백업·교체 실패 | 건드리지 않음 | `appliedVersion = A` |
| `nginx -t` 실패, reload 신호 전송 실패 | 신호를 받지 않음, 파일은 A로 되돌림 | `appliedVersion = A` |
| reload 후 새 worker 확인 시간 초과 → A로 다시 검증·reload·확인 성공 | A | `appliedVersion = A` |
| 위에서 A 재적용도 확인 못 함 | A인지 B인지 모름 | `.prev` 보존, `appliedVersion = null`, 다음 주기에는 새 목록 조회 전 A 복구부터 재시도 |
| 적용 도중 프로세스 종료 뒤 같은 컨테이너에서 재실행 | 모름 | A 복원·검증·reload 확인까지 `null`. 이후 조회가 실패해도 확인된 A를 보고 |
| WAF 컨테이너 재시작 | nginx가 볼륨의 마지막 정상 룰을 새로 읽음 | `.prev`가 있으면 복구 검증·reload 후 보고. 미완료 표시가 없고 메타데이터가 완전하면 reload 없이 `SUCCESS` 가능 |

### WAF가 '적용 확인'을 판단하는 방법

- reload 확인은 **reload 전의 worker가 모두 새 worker로 바뀐 것**을 `/proc`에서 확인하는 것이다. worker를 볼 수 없으면 확인할 수 없으므로 reload를 보내지 않고 실패로 처리한다.
- 룰 파일은 nginx 시작 전(`prepare`)이나 확인된 reload로만 바뀐다. 따라서 아래 두 표시가 없고 nginx가 실행 중이면 nginx는 룰 파일대로 동작한다.
  - `blacklist.conf.prev`: 적용 또는 복구 중(실행 설정을 확인하기 전에는 보존)
  - `/tmp/waf-blacklist-sync.unverified`: 이전 버전이 남긴 미확인 표시. 준비 단계만으로 지우지 않고 확인된 적용·복구 후 제거
- 이때 룰 파일 머리 주석의 version과 `# 차단 제외:` 주석을 `appliedVersion`, `excludedIps`로 보낸다. `# 차단 제외 메타데이터: 1`이 있어야 완전한 제외 목록으로 판단한다. 구버전 파일처럼 메타데이터가 없으면 둘 다 `null`로 보내며, 다음 정상 조회·적용으로 갱신한다.
- 복구 파일 교체·검증·reload 실패도 `STATE_WRITE_FAILED` / `NGINX_TEST_FAILED` / `RELOAD_FAILED` / `RELOAD_TIMEOUT`으로 보고한다. 복구가 완료되지 않은 상태에서는 실제 적용 version과 제외 목록을 `null`로 유지한다.

## 7. 보고 시점과 연결 끊김 기준

- 동기화(기본 10초, `WAF_SYNC_INTERVAL`)가 끝날 때마다 한 번 보고한다. 적용 성공·실패 결과는 그 주기에 바로 보고되고, 목록이 바뀌지 않아도 같은 주기로 보고한다.
- 보고 요청은 연결 3초, 전체 5초 안에 끝나지 않으면 포기한다.
- 보고에 실패하면 차단 설정은 그대로 두고 다음 주기에 다시 보고한다. 같은 실패는 로그에 한 번만 남기고 복구되면 `상태 보고 복구`를 남긴다.
- 수동 동기화(`blacklist-sync.sh once`)는 보고하지 않는다. 다음 주기에 동기화 루프가 결과를 확인해 보고한다.
- 백엔드는 보고를 받은 시각을 직접 기록한다(WAF는 시각을 보내지 않는다).
- 마지막 보고 이후 **60초**가 지나면 '상태 미확인'으로 표시한다. 60초는 초기값이고 설정으로 바꿀 수 있게 한다.
- 상태 보고가 끊겼다고 기존 차단이 해제됐다고 표시하지 않는다.
- 상태 보고 요청이 성공했다고 `lastSyncResult`를 `SUCCESS`로 바꾸지 않는다. 이 필드는 목록 동기화 결과다.

## 8. 화면 상태 계산 (백엔드)

WAF는 사실만 보고하고, 백엔드가 **현재 DB 스냅샷 version**과 비교해 화면 상태를 정한다. 현재 DB version은 `BlacklistSnapshotService`와 같은 방식으로 계산한다.

| 판정 순서 | 조건 | 표시 |
| --- | --- | --- |
| 1 | 보고 없음 또는 마지막 수신 후 60초 초과 | 상태 미확인 |
| 2 | `lastSyncResult = FAILURE` | 동기화 실패 |
| 3 | `appliedVersion = null` | 상태 미확인 |
| 4 | 현재 DB version = `appliedVersion` | 적용 확인 |
| 5 | 두 version이 다름 | 반영 대기 |

- 실패 상태에서도 `appliedVersion`이 있으면 "마지막 적용 확인 목록은 유지 중" 같은 부가 정보를 보여줄 수 있다.
- 차단 제외 IP는 별도로 표시한다. '적용 확인'을 '등록된 모든 IP 차단 완료'로 표현하지 않는다.

## 9. 예시

B 적용 완료:

```json
{
  "wafId": "aws-waf-1",
  "attemptedVersion": "07a8ccd47057a099cf1ec175c5129ba695ae24c9248ec680ce0e2ccc7d728629",
  "appliedVersion": "07a8ccd47057a099cf1ec175c5129ba695ae24c9248ec680ce0e2ccc7d728629",
  "lastSyncResult": "SUCCESS",
  "excludedIps": [
    { "ip": "172.18.0.1", "reason": "TRUSTED_PROXY" }
  ],
  "error": null
}
```

B 실패 후 A 유지 확인(`nginx -t` 실패):

```json
{
  "wafId": "aws-waf-1",
  "attemptedVersion": "<B 64자리>",
  "appliedVersion": "<A 64자리>",
  "lastSyncResult": "FAILURE",
  "excludedIps": [],
  "error": { "code": "NGINX_TEST_FAILED", "message": "nginx -t 실패: [emerg] ..." }
}
```

reload 시간 초과 뒤 A 재적용도 확인 못 함:

```json
{
  "wafId": "aws-waf-1",
  "attemptedVersion": "<B 64자리>",
  "appliedVersion": null,
  "lastSyncResult": "FAILURE",
  "excludedIps": null,
  "error": {
    "code": "RELOAD_TIMEOUT",
    "message": "reload 실패: 10초 안에 새 worker가 확인되지 않음, 이전 룰 재적용도 실패(실제 적용 상태 확인 필요)"
  }
}
```

nginx가 실행 중이 아니어서 적용을 확인하지 못함:

```json
{
  "wafId": "aws-waf-1",
  "attemptedVersion": "<받은 version>",
  "appliedVersion": null,
  "lastSyncResult": "UNKNOWN",
  "excludedIps": null,
  "error": null
}
```

## 10. 백엔드 구현 시 확인할 점 (현재 코드 기준)

- **경로 허용**: `WafSyncSecurityConfig`는 `GET /internal/waf/blacklist`만 허용하고 나머지는 `denyAll`이다. `POST /internal/waf/sync-status`를 명시적으로 허용해야 한다.
- **CSRF**: 이 보안 체인은 CSRF 보호를 유지한다(커밋 `5d2c3a6b`). WAF의 POST에는 CSRF 토큰이 없으므로 그대로 두면 403이 된다. 처리 방법은 [변경 제안](#11-변경-제안-합의-필요) 1번이다.
- **권한**: `WafSyncTokenFilter`는 `WAF_BLACKLIST_READ`만 부여한다. 보고 경로에 어떤 권한을 요구할지 정한다(제안 2번).
- **응답**: 트랜잭션 커밋 후 `204`를 준다.
- **저장**: 10초마다 보고되므로 이력을 모두 쌓으면 WAF 한 대당 하루 8,640행이다. `wafId`별 최신 상태 1행 갱신을 권장한다.
- **검증(400)**: `wafId` 형식, version은 64자리 소문자 16진수 또는 `null`, `lastSyncResult` 값, 5절 일관성 규칙, 제외 사유 코드.
- **로그**: 토큰 헤더를 요청 로그에 남기지 않는다.

## 11. 변경 제안 (합의 필요)

WAF 구현 중 확인한 사항이다. 3번은 이번 보완에서 WAF에 반영했고, 나머지는 백엔드 구현 전에 확인할 계약 사항이다(1·2번은 백엔드 작업).

1. **보고 경로 CSRF 예외**: `csrf.ignoringRequestMatchers("/internal/waf/sync-status")`처럼 이 경로만 예외로 둔다. 이 체인은 세션·쿠키를 쓰지 않고(STATELESS, `NullSecurityContextRepository`) 커스텀 헤더 토큰으로 인증하므로, 브라우저가 자동으로 붙이는 자격 증명이 없어 CSRF 공격 대상이 아니다. 다른 경로의 CSRF 보호는 그대로 둔다.
2. **쓰기 권한 분리**: 토큰 필터가 `WAF_SYNC_STATUS_WRITE` 같은 권한을 함께 부여하고 보고 경로는 그 권한만 허용한다. 조회 권한과 구분해 두면 이후 권한 정리가 쉽다.
3. **제외 사유 `INVALID_FORMAT` 반영 완료(WAF)**: 백엔드와 WAF의 허용 형식 차이로 차단되지 않는 값도 `excludedIps`에 담는다. 백엔드 수신 DTO·사유 검증·프론트 표시에 이 코드를 포함해야 한다. 기존 IP 등록 검증 자체는 이번에 변경하지 않았다.
4. **오류 코드 목록 확정**: 4절의 7개 코드를 기준으로 하고, 백엔드는 모르는 코드도 문자열로 저장한다(WAF가 코드를 추가해도 400이 되지 않게).
5. **`message` 길이**: 최대 300자. DB 컬럼은 300자 이상(예: `VARCHAR(500)`)으로 둔다.
6. **`wafId` 형식**: 소문자·숫자·`.`·`_`·`-`, 64자 이하. WAF는 형식이 틀리면 보고를 끄고 경고만 남긴다(동기화는 계속).
7. **조회 실패 때의 `appliedVersion`**: 목록을 받지 못해도 nginx를 건드리지 않았으므로 마지막으로 확인한 version을 보낸다(재시작 직후처럼 확인 전이면 `null`). 화면 판정은 2순위 '동기화 실패'라 결과는 같고, 부가 정보에 쓰인다. 이 해석이 맞는지 확인한다.
8. **`excludedIps[].ip`**: WAF가 정규화한 값이 아니라 스냅샷의 문자열 그대로 보낸다(DB 행과 그대로 대조할 수 있게).
9. **만료 60초의 여유**: 정상 주기는 약 10초지만, reload 확인 시간 초과와 복구 reload가 겹치면 한 주기가 길어진다. 실제 nginx 재현에서 실패 주기 하나가 약 26초였고, 최악은 조회 10초 + reload 확인 10초 × 2 + 보고 5초 + 주기 10초(`nginx -t` 시간 별도)다. 60초는 유지하되 `WAF_SYNC_INTERVAL`을 20초 넘게 늘리면 함께 늘린다.

## 12. 검증

- 자동 테스트: `python3 -m unittest discover -s waf/tests -v`(CI `WAF script tests` 단계). 가짜 백엔드가 보고를 받아 본문·헤더·순서를 확인한다.
- 실제 nginx(일회용 WAF 컨테이너 + 가짜 백엔드)에서 확인한 결과는 [waf/README.md](../waf/README.md#검증-결과-로컬)에 있다.
- 실제 백엔드 API와의 연결은 백엔드 구현 후 확인한다.
