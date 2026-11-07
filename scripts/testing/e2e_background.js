import http from 'k6/http';
import exec from 'k6/execution';
import {Trend} from 'k6/metrics';
import {sha256} from 'k6/crypto';
import {shouldSendBackground} from './e2e_workload.js';

const records = new Trend('dg_client_request', true);
const rate = Number(__ENV.RUN_RATE);
const seconds = Number(__ENV.RUN_SECONDS);
const phase = __ENV.RUN_PHASE;
const target = __ENV.TARGET_URL;
const environment = __ENV.DG_ENVIRONMENT || 'local';
const ec2Raw = environment === 'ec2' ? open('./profiles/ec2-e2e-v1.json') : '';
const ec2 = ec2Raw ? JSON.parse(ec2Raw) : null;
if (!['local', 'ec2'].includes(environment)) throw new Error('지원하지 않는 환경');
if (environment === 'ec2' && (!ec2.executable || ec2.version !== 'ec2-e2e-v1'
    || __ENV.DG_EC2_CONTRACT_SHA256 !== sha256(ec2Raw, 'hex')))
  throw new Error('EC2 전용 실행기의 고정 계약이 필요합니다.');
const validTarget = environment === 'local' ? /^http:\/\/localhost(?::80)?\/$/.test(target)
  : target === 'https://security-juiceshop-kw.duckdns.org/';
if (![1, 3, 5].includes(rate) || !Number.isInteger(seconds) || seconds < 1 || seconds > 120
    || !validTarget
    || !['warmup', 'measurement'].includes(phase)) throw new Error('허용되지 않은 E2E 부하 조건');
export const options = {
  hosts: environment === 'local' ? {localhost: '127.0.0.1'} : {},
  insecureSkipTLSVerify: false,
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
  if (!shouldSendBackground(sequence, rate, seconds)) return;
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
