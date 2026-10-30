var SENSITIVE_HEADERS = ['cookie', 'authorization', 'set-cookie', 'proxy-authorization', 'x-api-key'];

function dump(r) {
    var masked = {};
    for (var key in r.headersIn) {
        masked[key] = SENSITIVE_HEADERS.indexOf(key.toLowerCase()) !== -1 ? '***MASKED***' : r.headersIn[key];
    }
    return JSON.stringify(masked);
}

export default { dump };
