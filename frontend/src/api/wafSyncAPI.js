import apiClient from "./apiClient";

const STATUS_CODES = new Set([
    'APPLIED',
    'PENDING',
    'FAILED',
    'UNKNOWN',
]);

export async function getWafSyncStatus(signal){
    const response = await apiClient.get(
        '/api/v1/waf/sync-status',
        {signal}
    );

    const data = response.data;

    const valid =
        data != null &&
    typeof data.wafId === 'string' &&
    STATUS_CODES.has(data.status) &&
    typeof data.stale === 'boolean' &&
    (
      data.excludedIps === null ||
      (
        Array.isArray(data.excludedIps) &&
        data.excludedIps.every(entry =>
          entry != null &&
          typeof entry.ip === 'string' &&
          typeof entry.reason === 'string'
        )
      )
    );

    if(!valid) {
        throw new Error('WAF 상태 응답 형식이 올바르지 않습니다.')
    }

    return data;


}

