import {backgroundRequestLimit, shouldSendBackground} from './e2e_workload.js';

export const options = {vus: 1, iterations: 1};
export default function () {
  for (const [rate, seconds, expected] of [[1, 30, 27], [1, 60, 54], [1, 120, 108], [3, 120, 348], [5, 120, 588]]) {
    if (backgroundRequestLimit(rate, seconds) !== expected) throw new Error('계획 건수 불일치');
    let sent = 0;
    for (let seq = 0; seq <= expected + 2; seq++) if (shouldSendBackground(seq, rate, seconds)) sent++;
    if (sent !== expected) throw new Error('종료 경계 초과 송신');
    if (!shouldSendBackground(expected - 1, rate, seconds) || shouldSendBackground(expected, rate, seconds))
      throw new Error('경계 판정 실패');
  }
  if (shouldSendBackground(-1, 1, 60) || shouldSendBackground(0.5, 1, 60)) throw new Error('잘못된 순번');
}
