export function formatDateTime(value){

    if(!value) return '-';

    // API 문자열에는 시간대 정보가 있어야 함
    if(typeof value === 'string' && !/(Z|[+-]\d{2}:\d{2})$/i.test(value)){
        return '시간대 확인 필요';
    }

    const date = new Date(value);

    if(Number.isNaN(date.getTime())){
        return '-';
    }

    return date.toLocaleString('ko-KR',{timeZone: 'Asia/Seoul',});
}