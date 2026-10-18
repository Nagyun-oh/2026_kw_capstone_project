import { useEffect, useRef } from 'react';
import useWafDetail from '../hooks/useWafDetail';
import { formatDateTime } from '../utils/dateTime';

const SEVERITY_TONES = {
  LOW: 'neutral',
  MEDIUM: 'info',
  HIGH: 'warning',
  CRITICAL: 'danger',
  UNKNOWN: 'neutral',
};

function DetailField({ label, children }) {
  return (
    <div className="log-detail-field">
      <dt>{label}</dt>
      <dd>{children ?? '—'}</dd>
    </div>
  );
}

function WafDetailModal({ threatId, onClose, onViewLog }) {
  const dialogRef = useRef(null);
  const isOpen = threatId != null;
  const { detail, loading, error } = useWafDetail(threatId);

  useEffect(() => {
    if (!isOpen) return;

    const dialog = dialogRef.current;
    if (!dialog) return;

    const previousOverflow = document.body.style.overflow;

    if (!dialog.open) {
      dialog.showModal();
    }

    document.body.style.overflow = 'hidden';

    return () => {
      if (dialog.open) {
        dialog.close();
      }

      document.body.style.overflow = previousOverflow;
    };
  }, [isOpen]);

  function handleCancel(event) {
    event.preventDefault();
    onClose();
  }

  function handleBackdropClick(event) {
    if (event.target === event.currentTarget) {
      onClose();
    }
  }

  return (
    <dialog
      ref={dialogRef}
      className="log-detail-modal"
      aria-labelledby="waf-detail-title"
      onCancel={handleCancel}
      onClick={handleBackdropClick}
    >
      <div className="log-detail-content">
        <header className="log-detail-header">
          <div>
            <p className="log-detail-eyebrow">WAF DETECTION DETAIL</p>

            <h2 id="waf-detail-title">
              WAF 탐지 상세
              {threatId != null && (
                <span className="log-detail-id">위협 #{threatId}</span>
              )}
            </h2>

            <p className="log-detail-subtitle">
              요청 정보와 WAF 규칙의 탐지 근거를 확인하세요.
            </p>
          </div>

          <button
            type="button"
            className="log-detail-close"
            aria-label="WAF 상세 닫기"
            onClick={onClose}
            autoFocus
          >
            ×
          </button>
        </header>

        <div className="log-detail-body" aria-busy={loading}>
          {loading && (
            <p className="log-detail-state" role="status">
              WAF 상세 정보를 불러오는 중입니다…
            </p>
          )}

          {!loading && error && (
            <p className="dashboard-error" role="alert">
              {error}
            </p>
          )}

          {!loading && !error && !detail && (
            <p className="log-detail-state">
              표시할 WAF 상세 정보가 없습니다.
            </p>
          )}

          {!loading && !error && detail && (
            <>
              <section className="log-detail-section">
                <h3>탐지 정보</h3>

                <dl className="log-detail-grid">
                  <DetailField label="탐지 출처">
                    {detail.threatType}
                  </DetailField>

                  <DetailField label="위험도">
                    <span
                      className={`data-badge data-badge--${
                        SEVERITY_TONES[detail.severity] ?? 'neutral'
                      }`}
                    >
                      {detail.severity || 'UNKNOWN'}
                    </span>
                  </DetailField>

                  <DetailField label="WAF 요청 ID">
                    {detail.requestId}
                  </DetailField>

                  <DetailField label="Anomaly score">
                    {detail.anomalyScore ?? '제공되지 않음'}
                  </DetailField>
                </dl>

                <p className="waf-detail-description">
                  {detail.description || '—'}
                </p>
              </section>

              <section className="log-detail-section">
                <h3>요청 정보</h3>

                <dl className="log-detail-grid">
                  <DetailField label="IP 주소">
                    {detail.clientIp}
                  </DetailField>

                  <DetailField label="HTTP 메서드">
                    {detail.requestMethod}
                  </DetailField>

                  <DetailField label="HTTP 응답 상태">
                    {detail.responseStatus}
                  </DetailField>

                  <DetailField label="연결된 원본 로그">
                    {detail.logId != null ? (
                      <button
                        type="button"
                        className="data-reference-button"
                        onClick={() => onViewLog(detail.logId)}
                      >
                        로그 #{detail.logId}
                      </button>
                    ) : (
                      '연결 없음'
                    )}
                  </DetailField>
                </dl>
              </section>

              <section className="log-detail-section">
                <h3>요청 경로</h3>

                <div className="log-detail-url">
                  {detail.requestPath || '—'}
                </div>
              </section>

              <section className="log-detail-section">
                <h3>시각 정보</h3>

                <p className="log-detail-help">
                  발생·수신 시각은 한국 시간으로 표시합니다.
                </p>

                <dl className="log-detail-grid">
                  <DetailField label="요청 발생 시각">
                    {detail.occurredAt
                      ? formatDateTime(detail.occurredAt)
                      : '변환되지 않음 · 원본 시각 확인'}
                  </DetailField>

                  <DetailField label="백엔드 수신 시각">
                    {formatDateTime(detail.receivedAt)}
                  </DetailField>

                  <DetailField label="WAF 원본 시각">
                    {detail.occurredAt
                        ? formatDateTime(detail.occurredAt)
                        : '시각 변환 불가'}
                  </DetailField>
                </dl>
              </section>

              <section className="log-detail-section">
                <h3>
                  탐지 규칙 ({detail.matchedRules?.length ?? 0}건)
                </h3>

                <p className="log-detail-help">
                  규칙 위험도는 WAF 원본 값입니다.
                  숫자 표기에서는 작은 값일수록 심각합니다.
                </p>

                <div className="waf-detail-rules">
                  {(detail.matchedRules ?? []).map((rule, index) => (
                    <article
                      className="waf-detail-rule"
                      key={`${rule.id}-${index}`}
                    >
                      <div className="waf-detail-rule__header">
                        <h4>규칙 {rule.id}</h4>

                        <span className="data-badge data-badge--neutral">
                          원본 위험도: {rule.severity ?? '미제공'}
                        </span>
                      </div>

                      <p className="waf-detail-rule__message">
                        {rule.message || '규칙 설명이 없습니다.'}
                      </p>

                      <dl className="log-detail-grid">
                        <DetailField label="탐지 대상 변수">
                          {rule.matchedVariable}
                        </DetailField>

                        <DetailField label="공격 유형 태그">
                          {rule.attackTypes?.length
                            ? rule.attackTypes.join(', ')
                            : '제공되지 않음'}
                        </DetailField>
                      </dl>
                    </article>
                  ))}
                </div>
              </section>
            </>
          )}
        </div>

        <footer className="log-detail-footer">
          <button
            type="button"
            className="dashboard-button dashboard-button--secondary"
            onClick={onClose}
          >
            닫기
          </button>
        </footer>
      </div>
    </dialog>
  );
}

export default WafDetailModal;