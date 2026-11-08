// AI 서비스가 만든 탐지 설명(reason) 문자열을 화면 표시용 구조로 나눈다.
// 형식(AI_new/ensemble_explainer.py):
//   [모델] 피처 [근거] +3.2 · 피처 [근거] +2.1 · 피처 +1.5 · 규칙도 일치: A, B · 검토 권장: 구조 특성 위주 판정
//   [규칙] 규칙 설명 [근거] · 규칙 설명 [근거]
// 접두어가 없는 예전 형식이나 해석할 수 없는 문자열은 source를 null로 두고 원문을 그대로 쓴다.

const SEPARATOR = ' · ';
const RULES_PREFIX = '규칙도 일치: ';
const REVIEW_PREFIX = '검토 권장';
const SOURCES = {
  '[모델] ': 'model',
  '[규칙] ': 'rule',
};

// "라벨 [근거] +1.2" → 근거와 기여도는 각각 없을 수 있다.
// 근거에 대괄호가 섞일 수 있어 마지막 ']'까지를 근거로 본다.
const ITEM_PATTERN = /^(.*?)(?: \[(.*)\])?(?: ([+-]\d+(?:\.\d+)?))?$/;

function parseItem(part) {
  const match = ITEM_PATTERN.exec(part);

  if (!match || !match[1]) {
    return { label: part, evidence: null, contribution: null };
  }

  return {
    label: match[1],
    evidence: match[2] ?? null,
    contribution: match[3] ?? null,
  };
}

export function parseAiReason(text) {
  const raw = typeof text === 'string' ? text.trim() : '';
  const prefix = Object.keys(SOURCES).find((key) => raw.startsWith(key));

  if (!prefix) {
    return { source: null, items: [], rules: [], review: false, raw };
  }

  const items = [];
  let rules = [];
  let review = false;

  raw
    .slice(prefix.length)
    .split(SEPARATOR)
    .map((part) => part.trim())
    .filter(Boolean)
    .forEach((part) => {
      if (part.startsWith(RULES_PREFIX)) {
        rules = part
          .slice(RULES_PREFIX.length)
          .split(', ')
          .filter(Boolean);
      } else if (part.startsWith(REVIEW_PREFIX)) {
        review = true;
      } else {
        items.push(parseItem(part));
      }
    });

  return { source: SOURCES[prefix], items, rules, review, raw };
}
