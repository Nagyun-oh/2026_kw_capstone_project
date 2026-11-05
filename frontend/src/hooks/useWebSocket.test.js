import {act, renderHook} from '@testing-library/react';
import {Client} from '@stomp/stompjs';
import {toast} from 'react-toastify';
import {emitE2ETrace} from '../utils/e2eTrace';
import useWebSocket from './useWebSocket';

let mockOptions;
let mockReceive;
const mockActive = new Set();

jest.mock('sockjs-client', () => jest.fn());
jest.mock('../api/apiClient', () => ({get: jest.fn()}));
jest.mock('../utils/e2eTrace', () => ({emitE2ETrace: jest.fn()}));
jest.mock('@stomp/stompjs', () => ({
  ReconnectionTimeMode: {EXPONENTIAL: 'exponential'},
  Client: jest.fn(options => {
    mockOptions = options;
    return {
      activate: jest.fn(), deactivate: jest.fn(),
      subscribe: jest.fn((destination, receive) => { mockReceive = receive; }),
    };
  }),
}));
// 실제 hook의 판단을 검사한다. 소켓·toast는 대역이며 실제 브라우저 검증이 아니다.
jest.mock('react-toastify', () => ({toast: {
  isActive: jest.fn(id => mockActive.has(id)),
  error: jest.fn((text, options) => mockActive.add(options.toastId)),
  update: jest.fn(),
}}));

const first = {alertId: 'recovery-alert-1', revision: 1, eventType: 'CREATED',
  type: 'WAF Detection', sources: ['WAF'], ip: '192.0.2.123'};
const second = {...first, revision: 2, eventType: 'UPDATED',
  type: 'WAF + AI Detection', sources: ['WAF', 'AI']};

function deliver(message) {
  act(() => mockReceive({body: JSON.stringify(message)}));
}

beforeEach(() => {
  jest.useFakeTimers();
  jest.clearAllMocks();
  mockActive.clear();
  // CRA의 resetMocks 설정이 각 테스트 전 대역 구현을 초기화한다.
  Client.mockImplementation(options => {
    mockOptions = options;
    return {activate: jest.fn(), deactivate: jest.fn(),
      subscribe: jest.fn((destination, receive) => { mockReceive = receive; })};
  });
  toast.isActive.mockImplementation(id => mockActive.has(id));
  toast.error.mockImplementation((text, options) => mockActive.add(options.toastId));
  jest.spyOn(console, 'log').mockImplementation(() => {});
});
afterEach(() => {
  jest.clearAllTimers();
  jest.useRealTimers();
  jest.restoreAllMocks();
});

test('동일 revision 재전달·이전 revision 역전은 팝업과 갱신을 중복 생성하지 않는다', () => {
  const changed = jest.fn();
  const view = renderHook(() => useWebSocket(changed));
  act(() => mockOptions.onConnect({}));
  deliver(first);
  deliver(first);
  deliver(second);
  deliver(first);
  deliver(second);
  expect(toast.error).toHaveBeenCalledTimes(1);
  expect(toast.error).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({
    toastId: 'request-alert-recovery-alert-1', autoClose: false,
  }));
  expect(toast.update).toHaveBeenCalledTimes(1);
  expect(changed).toHaveBeenCalledTimes(2);
  expect(emitE2ETrace.mock.calls.filter(([stage]) => stage === 'received')).toHaveLength(2);
  view.unmount();
});

test('관리자가 닫은 팝업은 재전달·후속 갱신으로 다시 열리지 않는다', () => {
  const view = renderHook(() => useWebSocket());
  act(() => mockOptions.onConnect({}));
  deliver(first);
  mockActive.clear(); // 관리자가 닫은 상황
  deliver(first);
  deliver(second);
  expect(toast.error).toHaveBeenCalledTimes(1);
  expect(toast.update).not.toHaveBeenCalled();
  view.unmount();
});

test('같은 화면에서 재연결돼도 이미 받은 알림을 새 팝업으로 만들지 않는다', () => {
  const view = renderHook(() => useWebSocket());
  act(() => mockOptions.onConnect({}));
  deliver(first);
  act(() => mockOptions.onConnect({}));
  deliver(first);
  expect(toast.error).toHaveBeenCalledTimes(1);
  view.unmount();
});
