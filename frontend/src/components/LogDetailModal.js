import {useEffect,useRef} from 'react';
import { formatDateTime } from '../utils/dateTime';

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

function getStatusTone(statusCode){
  const code = Number(statusCode);

  if(code >= 500) return 'danger';
  if(code >= 400) return 'warning';
  if(code >= 300) return 'info';
  if(code >= 200) return 'success';

  return 'neutral';
}

function LogDetailModal({
  isOpen,
  log,
  loading,
  error,
  onClose,
}){
  const dialogRef = useRef(null);

  useEffect(()=> {
    if(!isOpen) return;

    const dialog = dialogRef.current;
    if(!dialog) return;

    const previoustOverflow = document.body.style.overflow;

    if(!dialog.open){
      dialog.showModal();
    }

    // 모달을 보는 동안 배경 페이지 스크롤 방지
    document.body.style.overflow = 'hidden';

    return () => {
      if(dialog.open){
        dialog.close();
      }
    document.body.style.overflow = previoustOverflow;
    };
  },[isOpen]);


  function handleCancel(event){
    // Escape로 닫을 때 부모의 isOpen 상태도 함께 변경
    event.preventDefault();
    onClose();
  }

  function handleBackdropClick(event){
    // 내부 콘텐츠 클릭은 제외하고 배경 클릭만 처리
    if(event.target === event.currentTarget){
      onClose();
    }
  }

  return(
    <dialog
      ref={dialogRef}
      className='log-detail-modal'
      aria-labelledby='log-detail-title'
      onCancel={handleCancel}
      onClick={handleBackdropClick}
    >
      <div className="log-detail-content">
        <header className='log-detail-header'>
      <div>
        <p className='log-detail-eyebrow'>
          REQUEST DETAIL
        </p>

        <h2 id="log-detail-title">
          원본 로그 상세
          {log && (
            <span className='log-detail-id'>
              #{log.id}
            </span>
          )}
        </h2>

        <p className='log-detail-subtitle'>
          수집된 HTTP 요청과 원본 데이터를 확인하세요.
        </p>
      </div>
      <button
        type="button"
        className='log-detail-close'
        aria-label = '로그 상세 닫기'
        onClick={onClose}
        autoFocus
      >
        x
      </button>
      </header>


      <div
        className='log-detail-body'
        aria-busy={loading}
      >
        {loading && (
          <p className='log-detail-state' role='status'>
            로그를 불러오는 중입니다…
          </p>
        )}
        {!loading && error && (
          <p className='dashboard-error' role='alert'>
            {error}
          </p>
        )}

        {!loading && !error && !log && (
          <p className='log-detail-state'>
            표시할 로그가 없습니다.
          </p>
        )}

        {!loading && !error && log &&(
          <>
          <section className='log-detail-section'>
            <h3>요청 정보</h3>

            <dl className='log-detail-grid'>
              <div className='log-detail-field'>
                <dt>IP 주소</dt>
                <dd className='log-detail-mono'>
                    {log.ipAddress || '-'}
                </dd>
              </div>

              <div className='log-detail-field'>
                <dt>HTTP 메서드</dt>
                <dd>
                  <span className='data-badge data-badge--neutral'>
                    {log.requestMethod || '-'}
                  </span>
                </dd>
              </div>

              <div className='log-detail-field'>
                <dt>HTTP 상태</dt>
                <dd>
                  <span
                    className={`data-badge data-badge--${getStatusTone(
                      log.statusCode
                    )}`}
                  >
                    {log.statusCode ?? '-'}
                  </span>
                </dd>
              </div>

              <div className='log-detail-field'>
                <dt>기록 시각</dt>
                <dd>{formatDateTime(log.createdAt)}</dd>
              </div>
            </dl>
          </section>

          <section className='log-detail-section'>
            <h3>요청 URL</h3>

            <div className='log-detail-url'>
              {log.requestUrl || '-'}
            </div>
          </section>
                  
          <section className='log-detail-section'>
            <h3>전체 원본 로그</h3>

            <p className='log-detail-help'>
              JSON 형식의 데이터는 들여쓰기하여 표시합니다.
            </p>
            
            <pre
              className='log-detail-raw'
              tabIndex={0}
              aria-label='전체 원본 로그'
            >
              <code>{formatRawLog(log.rawLog)}</code>
            </pre>
          </section>
          </>
        )}
      </div>

      <footer className='log-detail-footer'>
        <button
          type='button'
          className='dashboard-button dashboard-button--secondary'
          onClick={onClose}
        >
          닫기
        </button>
      </footer>
      </div>
    </dialog>
  );
}

export default LogDetailModal;