import http from "k6/http";
import {check} from "k6";

export const options = {
    vus: 1,
    iterations: 3,
    thresholds:{
        http_req_failed: ["rate<0.01"],
        http_req_duration: ["p(95)<500"],
    },
};

const BASE_URL = __ENV.BASE_URL || "http://localhost:8080";

export default function() {
   
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
}

/*
 * Smoke Test
 *
 * 목적:
 * - 백엔드 서버가 정상 실행 중인지 빠르게 확인한다.
 * - 주요 조회 API가 200 OK를 반환하는지 검증한다.
 * - 본격적인 부하 테스트 전에 API 접근 가능 여부를 점검한다.
 *
 * 테스트 대상:
 * - GET /api/v1/logs
 * - GET /api/v1/threats
 * - GET /api/v1/blacklist
 *
 * 실행 방식:
 * - 가상 사용자 1명(vus: 1)
 * - 총 3회 반복(iterations: 3)
 *
 * 통과 기준:
 * - HTTP 요청 실패율이 1% 미만
 * - 전체 요청 중 95%가 500ms 미만으로 응답
*/