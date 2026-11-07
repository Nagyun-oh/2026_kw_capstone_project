// 일정 도착률 실행기의 종료 경계에서 반복이 하나 더 예약돼도 HTTP 송신 수를 고정한다.
export function backgroundRequestLimit(rate, seconds) {
  if (![1, 3, 5].includes(rate) || !Number.isInteger(seconds) || seconds < 1 || seconds > 120)
    throw new Error('부하 범위 오류');
  return Math.ceil(seconds * (rate * 10 - 1) / 10);
}

export function shouldSendBackground(sequence, rate, seconds) {
  return Number.isInteger(sequence) && sequence >= 0 && sequence < backgroundRequestLimit(rate, seconds);
}
