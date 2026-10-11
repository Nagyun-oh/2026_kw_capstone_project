import { useState } from 'react';
import TablePagination from './TablePagination';

const DANGER_LEVELS = {
  1: { label: 'MEDIUM', tone: 'info' },
  2: { label: 'MEDIUM', tone: 'info' },
  3: { label: 'HIGH', tone: 'warning' },
  4: { label: 'CRITICAL', tone: 'danger' },
  5: { label: 'CRITICAL', tone: 'danger' },
};

function BlacklistTable({
  blacklists,
  pageInfo,
  onPageChange,
  onSearch,
  onReset,
  onViewLog,
}) {
  const [form, setForm] = useState({
    ip: '',
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
    setForm({ ip: '', severity: '' });
    onReset();
  };

  return (
    <section className="data-panel" aria-label="차단 목록 IP">
      <header className="data-panel__header">
        <div>
          <h2>차단 목록 IP</h2>
          <p>목록에 등록된 IP와 등록 사유, 연관 위협을 확인하세요.</p>
        </div>

        <span className="data-count">
          목록 기준 {pageInfo.totalElements.toLocaleString('ko-KR')}건
        </span>
      </header>

      <form className="data-filters" onSubmit={handleSubmit}>
        <label className="data-field data-field--wide">
          <span>IP 주소</span>
          <input
            name="ip"
            value={form.ip}
            onChange={handleChange}
            placeholder="예: 192.168.0.1"
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
            {['MEDIUM','HIGH','CRITICAL'].map(severity => (
              <option key={severity} value={severity}>
                {severity}
              </option>
            ))}
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
        aria-label="차단 목록 데이터 표"
        tabIndex={0}
      >
        <table className="data-table data-table--blacklist">
          <colgroup>
            <col className="data-column-ip" />
            <col className="data-column-id" />
            <col className="data-column-reference" />
            <col />
            <col className="data-column-severity" />
          </colgroup>

          <thead>
            <tr>
              <th scope="col">IP 주소</th>
              <th scope="col">원인 위협</th>
              <th scope="col">원본 로그</th>
              <th scope="col">등록 사유</th>
              <th scope="col">위험도</th>
            </tr>
          </thead>

          <tbody>
            {blacklists.length === 0 ? (
              <tr>
                <td colSpan={5} className="data-empty">
                  표시할 차단 목록이 없습니다.
                  검색하거나 전체 데이터를 새로고침해주세요.
                </td>
              </tr>
            ) : (
              blacklists.map(entry => {
                const danger = DANGER_LEVELS[entry.dangerLevel];

                return (
                  <tr key={entry.id}>
                    <td className="data-mono data-ip">
                      {entry.ipAddress || '—'}
                    </td>

                    <td className="data-muted">
                      {entry.sourceThreatId != null
                        ? `#${entry.sourceThreatId}`
                        : '—'}
                    </td>

                    <td>
                      {entry.logId != null ? (
                        <button
                          type="button"
                          className="data-reference-button"
                          onClick={() => onViewLog(entry.logId)}
                          aria-label={`원본 로그 ${entry.logId} 상세 보기`}
                        >
                          #{entry.logId}
                        </button>
                      ) : (
                        <span className="data-muted">
                          {entry.sourceThreatId != null
                            ? '원본 로그 없음'
                            : '수동 등록'}
                        </span>
                      )}
                    </td>

                    <td className="data-description">
                      {entry.reason || '—'}
                    </td>

                    <td>
                      <span
                        className={`data-badge data-badge--${
                          danger?.tone ?? 'neutral'
                        }`}
                      >
                        {danger?.label ?? '미지정'}
                      </span>
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
        itemCount={blacklists.length}
        onPageChange={onPageChange}
        label="차단 목록"
      />
    </section>
  );
}

export default BlacklistTable;