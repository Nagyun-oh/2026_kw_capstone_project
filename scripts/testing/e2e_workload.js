// 일정 도착률 실행기의 종료 경계에서 반복이 하나 더 예약돼도 HTTP 송신 수를 고정한다.
// 허용 RPS는 호출자가 계약에서 넘긴다. 기본은 로컬·정식 기준선의 1·3·5다.
export function backgroundRequestLimit(rate, seconds, allowedRates = [1, 3, 5]) {
  if (!Array.isArray(allowedRates) || !allowedRates.includes(rate) || !Number.isInteger(seconds)
      || seconds < 1 || seconds > 120)
    throw new Error('부하 범위 오류');
  return Math.ceil(seconds * (rate * 10 - 1) / 10);
}

export function shouldSendBackground(sequence, rate, seconds, allowedRates = [1, 3, 5]) {
  return Number.isInteger(sequence) && sequence >= 0
    && sequence < backgroundRequestLimit(rate, seconds, allowedRates);
}
