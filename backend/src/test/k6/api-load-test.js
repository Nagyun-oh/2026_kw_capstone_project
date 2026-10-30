import http from "k6/http";
import {check,sleep} from "k6";

export const options = {
    stages: [
        {duration: "30s", target:10},
        {duration: "1m", target:10},
        {duration: "30s", target:0},

    ],
    thresholds:{
        http_req_failed: ["rate<0.01"],
        http_req_duration: ["p(95)<500"],
    },
};

const BASE_URL = __ENV.BASE_URL || "http://localhost:8080";

export default function () {
    const logs = http.get(`${BASE_URL}/api/v1/logs?page=0&size=20`);
    check(logs,{
        "logs status is 200": response => response.status ===200,
    });

    const threats = http.get(`${BASE_URL}/api/v1/threats?page=0&size=20`);
    check(threats,{
        "threats status is 200": response => response.status ===200,
    });

    const blacklists = http.get(`${BASE_URL}/api/v1/blacklist?page=0&size=20`);
    check(blacklists,{
        "blacklists status is 200": response => response.status ===200,
    });

    sleep(1);
}

/*
 * API Load Test
 *
 * 목적:
 * - 여러 사용자가 동시에 주요 조회 API를 호출하는 상황을 가정한다.
 * - 백엔드 API의 응답 시간, 실패율, 처리 안정성을 확인한다.
 * - Actuator/Micrometer 지표와 함께 서버 내부 상태를 분석하기 위한 부하를 만든다.
 *
 * 테스트 대상:
 * - GET /api/v1/logs
 * - GET /api/v1/threats
 * - GET /api/v1/blacklist
 *
 * 부하 패턴:
 * - 30초 동안 가상 사용자 10명까지 증가
 * - 1분 동안 가상 사용자 10명 유지
 * - 30초 동안 가상 사용자 0명까지 감소
 *
 * 통과 기준:
 * - HTTP 요청 실패율이 1% 미만
 * - 전체 요청 중 95%가 500ms 미만으로 응답
*/