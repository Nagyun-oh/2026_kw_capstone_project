import { useState } from 'react';
import TablePagination from './TablePagination';

const SEVERITY_TONES = {
  MEDIUM: 'info',
  HIGH: 'warning',
  CRITICAL: 'danger',
};

function ThreatTable({
  threats,
  isNewThreat,
  pageInfo,
  onPageChange,
  onSearch,
  onReset,
  onViewLog,
}) {
  const [form, setForm] = useState({
    threatType: '',
    severity: '',
  });

  const handleChange = event => {
    const { name, value } = event.target;

    setForm(previous => ({
      ...previous,
      [name]: value,
    }));
  };

  const handleSubmit = event => {
    event.preventDefault();
    onSearch(form);
  };

  const handleReset = () => {
    setForm({ threatType: '', severity: '' });
    onReset();
  };

  return (
    <section
      className={`data-panel${isNewThreat ? ' data-panel--highlight' : ''}`}
      aria-label="위협 탐지 목록"
    >
      <header className="data-panel__header">
        <div>
          <div className="data-panel__title">
            <h2>위협 탐지</h2>

            {isNewThreat && (
              <span className="data-badge data-badge--danger" role="status">
                새 알림
              </span>
            )}
          </div>

          <p>탐지된 위협과 위험도를 확인하고 원본 로그를 조회하세요.</p>
        </div>

        <span className="data-count">
          목록 기준 {pageInfo.totalElements.toLocaleString('ko-KR')}건
        </span>
      </header>

      <form className="data-filters" onSubmit={handleSubmit}>
        <label className="data-field data-field--wide">
          <span>탐지 유형</span>
          <input
            name="threatType"
            value={form.threatType}
            onChange={handleChange}
            placeholder="예: AI 탐지"
          />
        </label>

        <label className="data-field">
          <span>위험도</span>
          <select
            name="severity"
            value={form.severity}
            onChange={handleChange}
          >
            <option value="">전체 위험도</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="HIGH">HIGH</option>
            <option value="CRITICAL">CRITICAL</option>
          </select>
        </label>

        <div className="data-filters__actions">
          <button
            type="submit"
            className="dashboard-button dashboard-button--primary"
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
              <th scope="col">원본 로그</th>
              <th scope="col">탐지 유형</th>
              <th scope="col">위험도</th>
              <th scope="col">탐지 설명</th>
            </tr>
          </thead>

          <tbody>
            {threats.length === 0 ? (
              <tr>
                <td colSpan={5} className="data-empty">
                  표시할 위협 기록이 없습니다.
                  검색하거나 전체 데이터를 새로고침해주세요.
                </td>
              </tr>
            ) : (
              threats.map(threat => (
                <tr key={threat.id}>
                  <td className="data-muted">#{threat.id}</td>

                  <td>
                    {threat.logId != null ? (
                      <button
                        type="button"
                        className="data-reference-button"
                        onClick={() => onViewLog(threat.logId)}
                        aria-label={`원본 로그 ${threat.logId} 상세 보기`}
                      >
                        #{threat.logId}
                      </button>
                    ) : (
                      <span className="data-muted">연결 없음</span>
                    )}
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
              ))
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