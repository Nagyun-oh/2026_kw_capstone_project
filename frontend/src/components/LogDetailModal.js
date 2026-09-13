import React from 'react';

function formatRawLog(rawLog) {
  if (!rawLog) return '-';

  let parsed;
  try {
    parsed = JSON.parse(rawLog);
  } catch {
    return rawLog;
  }

  if (parsed && typeof parsed.headers === 'string') {
    try {
      parsed.headers = JSON.parse(parsed.headers);
    } catch {
      // JSON이 아닌 헤더는 원래 문자열 유지
    }
  }

  return JSON.stringify(parsed, null, 2);
}

function LogDetailModal({
    isOpen,
    log,
    loading,
    error,
    onClose,
}) {
    if(!isOpen){
        return null;
    }

    return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 1000,
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        padding: '20px',
        backgroundColor: 'rgba(0, 0, 0, 0.5)',
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="log-detail-title"
        onClick={event => event.stopPropagation()}
        style={{
          width: 'min(700px, 100%)',
          maxHeight: '85vh',
          overflowY: 'auto',
          padding: '24px',
          borderRadius: '10px',
          backgroundColor: 'white',
          boxShadow: '0 10px 30px rgba(0, 0, 0, 0.25)',
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <h2 id="log-detail-title">원본 로그 상세</h2>

          <button type="button" onClick={onClose}>
            닫기
          </button>
        </div>

        {loading && <p role="status">로그를 불러오는 중입니다...</p>}

        {error && (
          <p role="alert" style={{ color: 'red' }}>
            {error}
          </p>
        )}

        {!loading && !error && log && (
          <>
            <table
              style={{
                width: '100%',
                borderCollapse: 'collapse',
                marginBottom: '20px',
              }}
            >
              <tbody>
                <tr>
                  <th style={{ textAlign: 'left' }}>로그 번호</th>
                  <td>#{log.id}</td>
                </tr>
                <tr>
                  <th style={{ textAlign: 'left' }}>IP</th>
                  <td>{log.ipAddress}</td>
                </tr>
                <tr>
                  <th style={{ textAlign: 'left' }}>HTTP Method</th>
                  <td>{log.requestMethod}</td>
                </tr>
                <tr>
                  <th style={{ textAlign: 'left' }}>요청 URL</th>
                  <td>{log.requestUrl}</td>
                </tr>
                <tr>
                  <th style={{ textAlign: 'left' }}>Status</th>
                  <td>{log.statusCode}</td>
                </tr>
                <tr>
                  <th style={{ textAlign: 'left' }}>발생 시각</th>
                  <td>
                    {log.createdAt
                      ? new Date(log.createdAt).toLocaleString()
                      : '-'}
                  </td>
                </tr>
              </tbody>
            </table>

            <h3>전체 원본 로그</h3>

            <pre
              style={{
                padding: '15px',
                borderRadius: '6px',
                backgroundColor: '#f4f4f4',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                overflowX: 'auto',
              }}
            >
              {formatRawLog(log.rawLog)}
            </pre>
          </>
        )}
      </div>
    </div>
  );
}

export default LogDetailModal;