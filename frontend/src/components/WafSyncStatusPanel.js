import { formatDateTime } from '../utils/dateTime';

const STATUS_INFO = {
  APPLIED: {
    label: '적용 확인',
    tone: 'success',
    description:
      '현재 DB 블랙리스트와 WAF가 적용 확인한 목록의 version이 같습니다.',
  },

  PENDING: {
    label: '반영 대기',
    tone: 'warning',
    description:
      '현재 DB 블랙리스트와 WAF가 적용 확인한 목록의 version이 다릅니다.',
  },

  FAILED: {
    label: '동기화 실패',
    tone: 'danger',
    description:
      '최근 목록 동기화가 실패했습니다. 아래 오류와 적용 version을 확인해주세요.',
  },

  UNKNOWN: {
    label: '상태 미확인',
    tone: 'neutral',
    description:
      '현재 WAF 적용 상태를 확인할 수 없습니다. 차단이 해제됐다는 의미는 아닙니다.',
  },
};

const EXCLUSION_REASONS = {
  LOOPBACK: '루프백 주소',
  UNSPECIFIED_ADDRESS: '미지정 주소',
  GATEWAY: 'Docker 게이트웨이',
  TRUSTED_PROXY: '신뢰 프록시',
  CONFIGURED_EXCLUSION: '설정에 따른 제외',
  INVALID_FORMAT: 'WAF가 지원하지 않는 IP 형식',
};

function WafSyncStatusPanel({
  data,
  isLoading,
  errorMessage,
  onRefresh,
}) {
  // 조회 실패 시 이전 APPLIED를 현재 상태로 표시하지 않는다.
  const statusCode = errorMessage
    ? 'UNKNOWN'
    : data?.status ?? 'UNKNOWN';

  const statusInfo =
    STATUS_INFO[statusCode] ?? STATUS_INFO.UNKNOWN;

  const badge = isLoading
    ? { label: '조회 중…', tone: 'neutral' }
    : statusInfo;

  const historical = Boolean(errorMessage || data?.stale);

  const excludedIps = data?.excludedIps;

  return (
    <section
      className="data-panel waf-sync-panel"
      aria-labelledby="waf-sync-title"
      aria-busy={isLoading}
    >
      <header className="data-panel__header">
        <div>
          <h2 id="waf-sync-title">WAF 블랙리스트 동기화</h2>

          <p>
            DB 차단 목록의 WAF 반영 상태를 10초마다 확인합니다.
          </p>
        </div>

        <div className="waf-sync-panel__actions">
          <span
            className={`data-badge data-badge--${badge.tone}`}
            role="status"
          >
            {badge.label}
          </span>

          <button
            type="button"
            className="dashboard-button dashboard-button--secondary"
            onClick={onRefresh}
            disabled={isLoading}
          >
            상태 새로고침
          </button>
        </div>
      </header>

      <div className="waf-sync-panel__body">
        {errorMessage && (
          <p className="dashboard-error" role="alert">
            {errorMessage}
          </p>
        )}

        {!isLoading && (
          <p className="waf-sync-panel__description">
            {statusInfo.description}
          </p>
        )}

        {!isLoading && !errorMessage && !data?.receivedAt && (
          <p className="waf-sync-panel__notice">
            아직 WAF 상태 보고를 받지 못했습니다.
          </p>
        )}

        {!errorMessage && data?.receivedAt && data.stale && (
          <p className="waf-sync-panel__notice">
            최근 보고가 없거나 보고 시각을 확인할 수 없습니다.
            아래 정보는 마지막 보고 기준입니다.
          </p>
        )}

        {errorMessage && data && (
          <p className="waf-sync-panel__notice">
            아래에는 마지막으로 조회한 정보를 표시합니다.
            현재 상태로 판단하지 마세요.
          </p>
        )}

        <dl className="waf-sync-panel__facts">
          <div>
            <dt>WAF 식별값</dt>
            <dd>{data?.wafId ?? '확인 전'}</dd>
          </div>

          <div>
            <dt>마지막 보고 시각 · 한국 시간</dt>
            <dd>
              {data?.receivedAt
                ? formatDateTime(data.receivedAt)
                : '보고 없음'}
            </dd>
          </div>

          <div>
            <dt>상태 확인 시각 · 한국 시간</dt>
            <dd>
              {data?.checkedAt
                ? formatDateTime(data.checkedAt)
                : '조회 전'}
            </dd>
          </div>
        </dl>

        {data?.error && (
          <div className="waf-sync-panel__failure">
            <strong>
              {historical ? '마지막 보고의 오류' : '동기화 오류'}
            </strong>

            <code>{data.error.code}</code>
            <p>{data.error.message}</p>
          </div>
        )}

        <div className="waf-sync-panel__exclusions">
          <h3>
            차단 제외 IP
            {historical ? ' · 마지막 보고 기준' : ''}
          </h3>

          {excludedIps == null ? (
            <p className="data-muted">
              적용된 목록의 제외 IP를 확인하지 못했습니다.
            </p>
          ) : excludedIps.length === 0 ? (
            <p className="data-muted">
              보고된 목록에 차단 제외 IP가 없습니다.
            </p>
          ) : (
            <>
              <p className="waf-sync-panel__notice">
                다음 {excludedIps.length}개 값은 보고된 적용 목록에서
                차단 대상에서 제외됐습니다.
              </p>

              <div className="data-table-scroll">
                <table className="data-table waf-sync-panel__table">
                  <thead>
                    <tr>
                      <th scope="col">IP 또는 원본 값</th>
                      <th scope="col">제외 사유</th>
                    </tr>
                  </thead>

                  <tbody>
                    {excludedIps.map((entry, index) => (
                      <tr
                        key={`${entry.ip}-${entry.reason}-${index}`}
                      >
                        <td>
                          <code>
                            {entry.ip === ''
                              ? '(빈 문자열)'
                              : entry.ip}
                          </code>
                        </td>

                        <td>
                          {EXCLUSION_REASONS[entry.reason]
                            ?? entry.reason}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>

        {data && (
          <details className="waf-sync-panel__versions">
            <summary>
              {historical ? '마지막 조회의 ' : ''}
              version 상세
            </summary>

            <dl>
              <div>
                <dt>DB 목록 version · 조회 시점 기준</dt>
                <dd>
                  <code>{data.currentVersion ?? '미확인'}</code>
                </dd>
              </div>

              <div>
                <dt>WAF 시도 version</dt>
                <dd>
                  <code>{data.attemptedVersion ?? '미확인'}</code>
                </dd>
              </div>

              <div>
                <dt>WAF 적용 확인 version</dt>
                <dd>
                  <code>{data.appliedVersion ?? '미확인'}</code>
                </dd>
              </div>
            </dl>
          </details>
        )}

        <p className="waf-sync-panel__footnote">
          적용 확인은 WAF 설정 반영 기준입니다.
          제외 IP를 포함한 모든 등록 IP의 차단 완료를 의미하지 않으며,
          개별 요청의 실제 차단 여부는 별도 검증이 필요합니다.
        </p>
      </div>
    </section>
  );
}

export default WafSyncStatusPanel;