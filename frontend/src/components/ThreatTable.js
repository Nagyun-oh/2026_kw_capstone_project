import { useState } from 'react';
import TablePagination from './TablePagination';

const EMPTY_FORM = {
  source: '',
  severity: '',
};

const SEVERITY_TONES = {
  LOW: 'neutral',
  MEDIUM: 'info',
  HIGH: 'warning',
  CRITICAL: 'danger',
  UNKNOWN: 'neutral',
};

function ThreatTable({
  threats,
  isNewThreat,
  pageInfo,
  loading = false,
  error = '',
  onPageChange,
  onSearch,
  onReset,
  onViewLog,
  onViewWaf,
}) {
  const [form, setForm] = useState(EMPTY_FORM);

  function handleChange(event) {
    const { name, value } = event.target;

    setForm(previous => ({
      ...previous,
      [name]: value,
    }));
  }

  function handleSubmit(event) {
    event.preventDefault();
    onSearch(form);
  }

  function handleReset() {
    setForm(EMPTY_FORM);
    onReset();
  }

  return (
    <section
      className={`data-panel${
        isNewThreat ? ' data-panel--highlight' : ''
      }`}
      aria-label="위협 탐지 목록"
      aria-busy={loading}
    >
      <header className="data-panel__header">
        <div>
          <div className="data-panel__title">
            <h2>위협 탐지</h2>

            {isNewThreat && (
              <span className="data-badge data-badge--danger">
                새 알림
              </span>
            )}
          </div>

          <p>AI와 WAF 탐지 결과를 출처별로 확인하세요.</p>
        </div>

        <span className="data-count">
          {loading
            ? '조회 중…'
            : error
              ? '조회 실패'
              : `목록 기준 ${pageInfo.totalElements.toLocaleString(
                  'ko-KR'
                )}건`}
        </span>
      </header>

      <form className="data-filters" onSubmit={handleSubmit}>
        <label className="data-field data-field--wide">
          <span>탐지 출처</span>

          <select
            name="source"
            value={form.source}
            onChange={handleChange}
          >
            <option value="">전체 출처</option>
            <option value="AI">AI Detection</option>
            <option value="WAF">WAF Detection</option>
          </select>
        </label>

        <label className="data-field">
          <span>위험도</span>

          <select
            name="severity"
            value={form.severity}
            onChange={handleChange}
          >
            <option value="">전체 위험도</option>
            <option value="LOW">LOW</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="HIGH">HIGH</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="UNKNOWN">UNKNOWN · 미확인</option>
          </select>
        </label>

        <div className="data-filters__actions">
          <button
            type="submit"
            className="dashboard-button dashboard-button--primary"
            disabled={loading}
          >
            검색
          </button>

          <button
            type="button"
            className="dashboard-button dashboard-button--secondary"
            onClick={handleReset}
          >
            초기화
          </button>
        </div>
      </form>

      {error && (
        <p className="dashboard-error" role="alert">
          {error}
        </p>
      )}

      <div
        className="data-table-scroll"
        role="region"
        aria-label="위협 탐지 데이터 표"
        tabIndex={0}
      >
        <table className="data-table data-table--threats">
          <colgroup>
            <col className="data-column-id" />
            <col className="data-column-reference" />
            <col className="data-column-type" />
            <col className="data-column-severity" />
            <col />
          </colgroup>

          <thead>
            <tr>
              <th scope="col">위협 번호</th>
              <th scope="col">상세</th>
              <th scope="col">탐지 유형</th>
              <th scope="col">위험도</th>
              <th scope="col">탐지 설명</th>
            </tr>
          </thead>

          <tbody>
            {loading ? (
              <tr>
                <td colSpan={5} className="data-empty" role="status">
                  위협 목록을 불러오는 중입니다…
                </td>
              </tr>
            ) : threats.length === 0 ? (
              <tr>
                <td colSpan={5} className="data-empty">
                  {error
                    ? '목록을 표시할 수 없습니다.'
                    : '검색 조건에 해당하는 위협 기록이 없습니다.'}
                </td>
              </tr>
            ) : (
              threats.map(threat => {
                const isWaf = threat.threatType === 'WAF Detection';

                return (
                  <tr key={threat.id}>
                    <td className="data-muted">#{threat.id}</td>

                    <td>
                      <div className="threat-detail-actions">
                        {isWaf && (
                          <button
                            type="button"
                            className="data-reference-button"
                            onClick={() => onViewWaf(threat.id)}
                            aria-label={`위협 ${threat.id} WAF 상세 보기`}
                          >
                            WAF 상세
                          </button>
                        )}

                        {threat.logId != null && (
                          <button
                            type="button"
                            className="data-reference-button"
                            onClick={() => onViewLog(threat.logId)}
                            aria-label={`원본 로그 ${threat.logId} 상세 보기`}
                          >
                            로그 #{threat.logId}
                          </button>
                        )}

                        {!isWaf && threat.logId == null && (
                          <span className="data-muted">연결 없음</span>
                        )}
                      </div>
                    </td>

                    <td className="data-description">
                      {threat.threatType || '—'}
                    </td>

                    <td>
                      <span
                        className={`data-badge data-badge--${
                          SEVERITY_TONES[threat.severity] ?? 'neutral'
                        }`}
                      >
                        {threat.severity || '미지정'}
                      </span>
                    </td>

                    <td className="data-description">
                      {threat.description || '—'}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      <TablePagination
        pageInfo={pageInfo}
        itemCount={threats.length}
        onPageChange={onPageChange}
        label="위협 탐지"
      />
    </section>
  );
}

export default ThreatTable;