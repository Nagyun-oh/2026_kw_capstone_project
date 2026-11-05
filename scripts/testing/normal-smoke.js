import http from 'k6/http';
import { Rate } from 'k6/metrics';

const ok = new Rate('normal_ok');
const rate = Number(__ENV.RUN_RATE || 1);
const seconds = Number(__ENV.RUN_SECONDS || 60);
const id = __ENV.RUN_ID || 'inspect-only';
const target = __ENV.TARGET_URL || 'http://127.0.0.1/';
const output = __ENV.SUMMARY_PATH || 'k6-summary.json';
const policy = __ENV.LOAD_POLICY_JSON ? JSON.parse(__ENV.LOAD_POLICY_JSON) : null;
if (policy && policy.version !== 'local-load-v1') {
  throw new Error('지원하지 않는 성능 기준 버전입니다.');
}

if (!Number.isInteger(rate) || rate < 1 || rate > 5 ||
    !Number.isInteger(seconds) || seconds < 1 || seconds > 120 ||
    !/^http:\/\/(127\.0\.0\.1|localhost)(:80)?\/$/.test(target)) {
  throw new Error('첫 버전은 로컬 WAF HTTP 80, 1~5회/초, 1~120초만 허용합니다.');
}

http.setResponseCallback(http.expectedStatuses(200));
export const options = {
  discardResponseBodies: true,
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(95)', 'p(99)'],
  scenarios: {
    normal: {
      executor: 'constant-arrival-rate',
      rate, timeUnit: '1s', duration: seconds + 's',
      preAllocatedVUs: 10, maxVUs: 10, gracefulStop: '15s',
    },
  },
  thresholds: {
    normal_ok: ['rate==1'],
    // 도착률 기반 실행의 계획 건수와 실제 건수는 별도로 기록한다.
    http_reqs: ['count>0'],
    iterations: ['count>0'],
    dropped_iterations: ['count==0'],
    ...(policy ? {
      http_req_duration: [
        `p(95)<=${policy.targets.http_p95_ms}`,
        `p(99)<=${policy.targets.http_p99_ms}`,
      ],
    } : {}),
  },
};

export default function () {
  const response = http.get(target + '?test_run=' + encodeURIComponent(id), {
    timeout: '10s', redirects: 0,
    tags: { name: 'normal-smoke', experiment: id },
  });
  ok.add(response.status === 200);
}

export function handleSummary(data) {
  return { [output]: JSON.stringify(data, null, 2) };
}

/*    
- 역할: k6 정상 요청 시나리오
- 구현된 기능k6 정상 요청·응답 검사·원본 결과 저장
*/
