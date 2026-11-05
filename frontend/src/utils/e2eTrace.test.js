import {emitE2ETrace} from './e2eTrace';

afterEach(() => { delete window.__DUALGUARD_E2E_TRACE__; });

test('관측기가 없으면 일반 화면 동작에 영향을 주지 않는다', () => {
  expect(() => emitE2ETrace('ready')).not.toThrow();
});

test('허용된 알림 식별자와 출처만 전달한다', () => {
  const observe = jest.fn();
  window.__DUALGUARD_E2E_TRACE__ = observe;
  emitE2ETrace('received', {alertId: 'id', revision: 2, sources: ['WAF', 'AI', 'OTHER'],
    ip: 'private', token: 'secret', body: 'secret'});
  const event = observe.mock.calls[0][0];
  expect(event.sources).toEqual(['WAF', 'AI']);
  expect(event).not.toHaveProperty('ip');
  expect(event).not.toHaveProperty('token');
  expect(event).not.toHaveProperty('body');
});

test('관측기의 예외를 알림 처리로 전파하지 않는다', () => {
  window.__DUALGUARD_E2E_TRACE__ = () => {throw new Error('test');};
  expect(() => emitE2ETrace('ready')).not.toThrow();
});
