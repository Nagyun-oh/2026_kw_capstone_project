// 요약 조회 API 함수
import apiClient from "./apiClient";

export async function getDashboardSummary(signal){
    // 검색 조건 없이 전체 건수 조회
    // 목록 데이터는 최소한으로 받기 위해 size를 1로 설정
    const config = {
        params: {page:0, size:1},
        signal,
    };

    /*
    
    현재는 기존 API를 재사용함
    이후 성능 개선 단계에서 필요하면 목록 데이터를 제외하고 건수만 반환하는 전용 집계 API로 바꿀 수 있음.
    */
    const [logsResponse, threatsResponse, blacklistResponse]=
        await Promise.all([
            apiClient.get('/api/v1/logs',config),
            apiClient.get('/api/v1/threats',config),
            apiClient.get('/api/v1/blacklist',config),
        ]);

    const summary = {
        totalLogs: logsResponse.data.totalElements,
        totalThreats: threatsResponse.data.totalElements,
        totalBlacklistEntries: blacklistResponse.data.totalElements,
    };

    // 잘못된 응답을 0건으로 표시하지 않도록 검사
    const valid = Object.values(summary).every(
        value => Number.isSafeInteger(value) && value >=0
    );

    if(!valid){
        throw new Error('요약 건수 응답이 올바르지 않습니다.');
    }

    return summary;
}