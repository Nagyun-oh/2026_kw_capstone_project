var SENSITIVE_HEADERS = ['cookie', 'authorization', 'set-cookie', 'proxy-authorization', 'x-api-key'];

function dump(r) {
    var masked = {};
    for (var key in r.headersIn) {
        masked[key] = SENSITIVE_HEADERS.indexOf(key.toLowerCase()) !== -1 ? '***MASKED***' : r.headersIn[key];
    }
    return JSON.stringify(masked);
}

// 두 nginx 시계 값은 밀리초 해상도다. 클라이언트 헤더는 사용하지 않는다.
function requestStart(r) {
    return (Number(r.variables.msec) - Number(r.variables.request_time)).toFixed(3);
}

export default { dump, requestStart };
