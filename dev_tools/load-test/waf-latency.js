// 사용자 응답 지연(T4): JuiceShop 정상 요청 목록(requests.json)을 일정 RPS로 보낸다(직접 vs WAF 경유 비교).
// 요청 순서는 반복 번호로 정해 두 조건에서 요청 구성이 같게 한다.
import http from 'k6/http';
import exec from 'k6/execution';

const MIX = JSON.parse(open('/scripts/requests.json'));
const BASE = __ENV.BASE;
const RATE = parseInt(__ENV.RATE, 10);
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
// 요청 목록은 AI가 모두 정상으로 판정함을 확인했다(최고 점수 0.18, 자동 등록 기준 0.8).
// 오탐이 나면 블랙리스트 자동 등록으로 k6 컨테이너 IP가 WAF에서 차단돼 측정이 깨진다.

export const options = {
  discardResponseBodies: true,
  scenarios: {
    load: {
      executor: 'constant-arrival-rate',
      rate: RATE,
      timeUnit: '1s',
      duration: __ENV.DURATION || '60s',
      preAllocatedVUs: Math.max(20, RATE),
      maxVUs: RATE * 5,
    },
  },
  summaryTrendStats: ['avg', 'med', 'p(95)', 'p(99)', 'max'],
};

http.setResponseCallback(http.expectedStatuses(200, 401));   // 로그인 실패(401)는 정상 응답으로 본다

export default function () {
  const r = MIX[exec.scenario.iterationInTest % MIX.length];
  const params = {
    headers: { 'User-Agent': UA, 'X-Load-Test': `t4-${__ENV.RUN}` },
    tags: { kind: r.group, target: __ENV.TARGET },
  };
  if (r.method === 'POST') {
    params.headers['Content-Type'] = 'application/json';
    http.post(BASE + r.path, r.body, params);
  } else {
    http.get(BASE + r.path, params);
  }
}
