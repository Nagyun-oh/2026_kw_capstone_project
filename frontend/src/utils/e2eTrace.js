// 자동화 브라우저가 설치한 콜백만 사용한다. 계정·IP·원문 메시지는 전달하지 않는다.
export function emitE2ETrace(kind, message = {}) {
  try {
    const observe = window.__DUALGUARD_E2E_TRACE__;
    if (typeof observe !== 'function') return;
    observe({
      kind,
      alertId: message.alertId,
      revision: message.revision,
      sources: Array.isArray(message.sources)
        ? message.sources.filter(source => ['WAF', 'AI'].includes(source))
        : [],
      browserAt: performance.now(),
    });
  } catch (_) {
    // 계측 오류는 알림 표시·재조회 동작에 영향을 주지 않는다.
  }
}
