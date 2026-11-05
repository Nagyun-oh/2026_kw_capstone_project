import http from 'k6/http';
import exec from 'k6/execution';
import {Trend} from 'k6/metrics';

const records = new Trend('dg_client_request', true);
const rate = Number(__ENV.RUN_RATE);
const seconds = Number(__ENV.RUN_SECONDS);
const phase = __ENV.RUN_PHASE;
const target = __ENV.TARGET_URL;
if (![1, 3, 5].includes(rate) || !Number.isInteger(seconds) || seconds < 1 || seconds > 120
    || !/^http:\/\/localhost(?::80)?\/$/.test(target)
    || !['warmup', 'measurement'].includes(phase)) throw new Error('허용되지 않은 E2E 부하 조건');
export const options = {
  hosts: {localhost: '127.0.0.1'},
  discardResponseBodies: true,
  summaryTrendStats: ['avg', 'med', 'p(95)', 'p(99)', 'max'],
  systemTags: ['status', 'name', 'scenario'],
  scenarios: {background: {executor: 'constant-arrival-rate', rate: rate * 10 - 1,
    timeUnit: '10s', duration: `${seconds}s`, preAllocatedVUs: 9, maxVUs: 9, gracefulStop: '10s'}},
  thresholds: {http_req_failed: ['rate==0'], dropped_iterations: ['count==0']},
};
export default function () {
  const header = (response, name) => {
    const key = Object.keys(response.headers).find(k => k.toLowerCase() === name);
    return key ? String(response.headers[key]) : '';
  };
  const sequence = exec.scenario.iterationInTest;
  const sentAt = Date.now();
  const response = http.get(target, {timeout: '10s', redirects: 0, headers: {
    'X-DualGuard-Test-Run': __ENV.RUN_ID, 'X-DualGuard-Test-Phase': phase,
    'X-DualGuard-Test-Kind': 'background', 'X-DualGuard-Test-Seq': String(sequence),
    'User-Agent': __ENV.PROBE_USER_AGENT,
  }, tags: {name: 'e2e-background'}});
  records.add(response.timings.duration, {request_id: header(response, 'x-request-id'),
    ingress: header(response, 'x-dualguard-request-start'),
    phase, kind: 'background', sequence: String(sequence), status: String(response.status),
    sent_at_ms: String(sentAt), ended_at_ms: String(Date.now())});
}
export function handleSummary(data) {
  return {[__ENV.SUMMARY_PATH]: JSON.stringify(data)};
}
