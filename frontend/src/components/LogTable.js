import {useState} from 'react';
import { formatDateTime } from '../utils/dateTime';

function getStatusTone(statusCode){
    if(statusCode>=500 && statusCode < 600) return 'danger';
    if(statusCode>=400 && statusCode < 500) return 'warning';
    if(statusCode>=300 && statusCode < 400) return 'info';
    if(statusCode>=200 && statusCode < 300) return 'success';

    return 'neutral';
  }

function LogTable({ 
  logs,
  pageInfo,
  onPageChange,
  onSearch,
  onReset, 
  onViewLog
}) {
  
  const [form,setForm] = useState({
    ip: "",
    method: "",
    statusCode: "",
  });

  const handleChange = event => {
    const {name,value} = event.target;

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
    const emptyForm = {
      ip: "",
      method: "",
      statusCode: "",
    };
    setForm(emptyForm);
    onReset();
  }

  return (
    <section className="data-panel" aria-label = "로그 목록">
      <header className="data-panel__header">
        <div>
          <h2>전체 로그</h2>
          <p>수집된 HTTP 요청을 검색하고 상세 내용을 확인하세요.</p>
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
            placeholder='예: 192.168.0.1'
          />
          </label>

          <label className="data-field">
            <span>메서드</span>
            <select
              name="method"
              value={form.method}
              onChange={handleChange}
            >
              <option value="">전체 메서드</option>
              {['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS']
                .map(method =>(
                  <option key={method} value={method}>
                      {method}
                  </option>
              ))}
            </select>
          </label>
        
        
        <label className="data-field">
          <span>HTTP 상태 코드</span>
          <input 
            type="number"
            name="statusCode"
            min="100"
            max="599"
            step="1"
            value={form.statusCode}
            onChange={handleChange}
            placeholder='예: 403'
        
          />
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
        aria-label="로그 데이터 표"
        tabIndex={0}
      >
        <table className="data-table data-table--logs">
          <colgroup>
              <col className="log-column-id"/>
              <col className="log-column-ip"/>
              <col className="log-column-method"/>
              <col/>
              <col className="log-column-status"/>
              <col className="log-column-time"/>
          </colgroup>

          <thead>
              <tr>
                <th scope="col">로그 번호</th>
                <th scope="col">IP 주소</th>
                <th scope="col">메서드</th>
                <th scope="col">요청 URL</th>
                <th scope="col">HTTP 상태</th>
                <th scope="col">기록 시각</th>
              </tr>
          </thead>

          <tbody>
            {logs.length === 0 ? (
              <tr>
                <td colSpan={6} className="data-empty">
                    표시할 로그가 없습니다.
                    검색하거나 전체 데이터를 새로고침해주세요.
                </td>
              </tr>
            ) : (
              logs.map(log => (
                <tr key={log.id}>
                  <td className="data-muted">#{log.id}</td>

                  <td className="data-mono">{log.ipAddress || '-'}</td>

                  <td>
                   <span className='data-badge data-badge--neutral'>
                    {log.requestMethod || '-'}
                   </span>
                  </td>

                  <td>
                    <button
                      type="button"
                      className='data-url-button'
                      title={log.requestUrl || '로그 상세 보기'}
                      aria-label={`로그 ${log.id} 상세 보기: ${
                        log.requestUrl || 'URL 없음'
                      }`}
                      onClick={() => onViewLog(log.id)}
                    >
                      {log.requestUrl || 'URL 없음'}
                    </button>
                  </td>

                  <td>
                    <span
                      className={`data-badge data-badge--${getStatusTone(
                        log.statusCode
                      )}`}
                    >
                      {log.statusCode ?? '—'}
                    </span>
                  </td>

                  <td className="data-time">
                    {formatDateTime(log.createdAt)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <footer className='data-pagination'>
        <span>
          현재 페이지 {logs.length.toLocaleString('ko-KR')}건
        </span>
        <nav className='data-pagination__controls' aria-label="로그 페이지">
          <button
            type="button"
            className='dashboard-button dashboard-button--secondary'
            disabled={pageInfo.number === 0}
            onClick={() => onPageChange(pageInfo.number-1)}
          >
            이전
          </button>

          <span className="data-pagination__position">
            {pageInfo.totalPages === 0 ? 0 : pageInfo.number +1}
            {' / '}
            {pageInfo.totalPages}
          </span>

          <button
            type="button"
            className='dashboard-button dashboard-button--secondary'
            disabled={pageInfo.number+1 >= pageInfo.totalPages}
            onClick={() => onPageChange(pageInfo.number+1)}
          >
            다음
          </button>
        </nav>
      </footer>
  </section>
  );
}

export default LogTable;