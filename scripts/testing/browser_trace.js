(() => {
  const latest = new Map();
  const seen = new Set();
  const closing = new Set();
  let ready = false;
  const send = event => {
    // Python binding은 메모리와 비밀값 없는 JSONL에만 저장한다.
    Promise.resolve(window.__dgBinding(event)).catch(() => {});
  };
  const visible = node => {
    if (!node || !node.getClientRects().length) return false;
    const box = node.getBoundingClientRect();
    const style = getComputedStyle(node);
    return style.visibility !== 'hidden' && style.display !== 'none'
      && box.bottom > 0 && box.top < innerHeight;
  };
  const scan = () => {
    for (const [alertId, event] of latest) {
      const node = document.getElementById(`request-alert-${alertId}`);
      if (!visible(node)) continue;
      for (const source of event.sources) {
        const key = `${alertId}:${source}`;
        if (!seen.has(key) && new RegExp(`\\b${source}\\b`).test(node.textContent)) {
          seen.add(key);
          send({...event, kind: 'dom', sources: [source], browserAt: performance.now(),
            duplicateCount: document.querySelectorAll(`[id="request-alert-${alertId}"]`).length});
        }
      }
      const policy = window.__dgAlertPolicy || {};
      const expected = policy[alertId];
      if (expected && expected.every(s => seen.has(`${alertId}:${s}`)) && !closing.has(alertId)) {
        closing.add(alertId);
        setTimeout(() => node.querySelector('button[aria-label="close"]')?.click(), 250);
      }
    }
  };
  Object.defineProperty(window, '__DUALGUARD_E2E_TRACE__', {value: event => {
    if (event.kind === 'ready') ready = true;
    if (event.kind === 'disconnected') ready = false;
    if (event.kind === 'received') latest.set(event.alertId, event);
    send(event);
    requestAnimationFrame(scan);
  }});
  Object.defineProperty(window, '__dgReady', {get: () => ready});
  setInterval(() => send({kind: 'heartbeat'}), 1000);
  const start = () => new MutationObserver(scan).observe(document.documentElement,
    {subtree: true, childList: true, characterData: true, attributes: true});
  if (document.documentElement) start();
  else document.addEventListener('DOMContentLoaded', start, {once: true});
})();
