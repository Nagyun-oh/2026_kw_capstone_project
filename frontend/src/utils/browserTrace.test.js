import fs from 'fs';
import path from 'path';

test('실제 DOM 가시성을 확인하고 같은 출처의 최초 표시만 기록한다', async () => {
  jest.useFakeTimers();
  const binding = jest.fn(() => Promise.resolve());
  window.__dgBinding = binding;
  const source = fs.readFileSync(path.resolve(process.cwd(), '../scripts/testing/browser_trace.js'), 'utf8');
  // 외부 네트워크 없이 브라우저 관측기의 실제 소스를 jsdom에서 실행한다.
  // eslint-disable-next-line no-new-func
  new Function(source)();
  const id = '1269a7b5-5db9-4f4b-a5ce-a4f09a56cabb';
  window.__DUALGUARD_E2E_TRACE__({kind: 'ready'});
  expect(window.__dgReady).toBe(true);
  window.__DUALGUARD_E2E_TRACE__({kind: 'received', alertId: id, revision: 1, sources: ['WAF']});
  jest.advanceTimersByTime(20);
  expect(binding.mock.calls.filter(([e]) => e.kind === 'dom')).toHaveLength(0);
  const node = document.createElement('div');
  node.id = `request-alert-${id}`;
  node.textContent = 'WAF Detection';
  node.getClientRects = () => [{}];
  node.getBoundingClientRect = () => ({top: 10, bottom: 50});
  document.body.appendChild(node);
  await Promise.resolve();
  node.textContent = 'WAF + AI Detection';
  window.__DUALGUARD_E2E_TRACE__({kind: 'received', alertId: id, revision: 2, sources: ['WAF', 'AI']});
  jest.advanceTimersByTime(20);
  await Promise.resolve();
  const dom = binding.mock.calls.map(([event]) => event).filter(e => e.kind === 'dom');
  expect(dom.filter(e => e.sources.includes('WAF'))).toHaveLength(1);
  expect(dom.filter(e => e.sources.includes('AI'))).toHaveLength(1);
  window.__DUALGUARD_E2E_TRACE__({kind: 'disconnected'});
  expect(window.__dgReady).toBe(false);
  document.body.removeChild(node);
  jest.clearAllTimers();
  jest.useRealTimers();
});
