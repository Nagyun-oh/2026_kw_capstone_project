// AI 탐지 설명의 근거를 원본 요청 위에 표시하기 위한 계산.
// 칠하는 위치는 '피처 값이 나온 문자열 위치'이며 글자 단위 SHAP 값이 아니다.
import { parseAiReason } from './aiReason';

// 화면 라벨 → 표시 종류와 범위.
// 라벨은 AI_new/ensemble_explainer.py의 FEATURE_LABELS와 같아야 하며, 긴 접두어를 먼저 검사한다.
// kind: pattern(근거 문자열 색칠) · range(잰 구간 밑줄) · compare(정상 트래픽 사전과 비교, 점선)
// region: method · path · query · url(경로+쿼리) · body · ua · extension · all
const FEATURE_RULES = [
  ['정상 트래픽에서 본 경로·파라미터 조합', 'compare', 'url'],
  ['처음 보는 경로·파라미터 조합', 'compare', 'url'],
  ['정상 트래픽 경로·파라미터 조합 출현', 'compare', 'url'],
  ['정상 트래픽에서 본 경로', 'compare', 'path'],
  ['처음 보는 경로', 'compare', 'path'],
  ['정상 트래픽 경로 출현', 'compare', 'path'],
  ['처음 보는 파라미터 비율', 'compare', 'query'],
  ['처음 보는 파라미터', 'pattern', 'query'],
  ['파라미터(본문 포함)', 'range', 'query'],
  ['파라미터', 'range', 'query'],
  ['가장 긴 파라미터 값', 'range', 'query'],
  ['가장 긴 값', 'range', 'query'],
  ['평균 값 길이', 'range', 'query'],
  ['숫자 값', 'range', 'query'],
  ['인코딩된 값', 'range', 'query'],
  ['URL 인코딩 문자', 'pattern', 'url'],
  ['URL 길이', 'range', 'url'],
  ['쿼리 길이', 'range', 'query'],
  ['본문 길이', 'range', 'body'],
  ['본문 있음', 'range', 'body'],
  ['본문 없음', 'range', 'body'],
  ['전체 길이', 'range', 'url'],
  ['경로 깊이', 'range', 'path'],
  ['특수문자 비율', 'range', 'url'],
  ['숫자 비율', 'range', 'url'],
  ['문자 비율', 'range', 'url'],
  ['특수문자', 'pattern', 'url'],
  ['메서드', 'range', 'method'],
  ['확장자', 'range', 'extension'],
  ['봇/스캐너 User-Agent', 'pattern', 'ua'],
  ['일반 User-Agent', 'range', 'ua'],
  ['User-Agent', 'range', 'ua'],
];

const KIND_CAPTIONS = {
  pattern: '근거 문자열',
  range: '잰 구간',
  compare: '정상 트래픽 사전과 비교',
  absent: '요청에 없음',
};

export function classifyFeature(label) {
  const rule = FEATURE_RULES.find(([prefix]) => label.startsWith(prefix));
  const [, kind, region] = rule ?? [null, 'pattern', 'all'];
  const value = /(\d+(?:\.\d+)?)\s*(개|자|회)?$/.exec(label);

  // 값이 0이거나 '없음'인 피처는 칠할 곳이 없으므로 '없음'으로 보여 준다.
  // 비교형의 0(예: 정상 트래픽 경로 출현 0회)은 요청에 없다는 뜻이 아니라 사전에 없다는 뜻이라 제외한다.
  if (kind !== 'compare' && (/없음$/.test(label) || (value && Number(value[1]) === 0))) {
    return { kind: 'absent', region };
  }

  return { kind, region };
}

// 퍼센트 인코딩을 풀면서 풀린 글자마다 원문 위치를 기억한다.
// AI의 unquote처럼 '+'는 공백으로 바꾸지 않는다.
export function decodeWithMap(raw) {
  let text = '';
  const map = [];
  let i = 0;

  const byteAt = (at) => (raw[at] === '%' && /^[0-9a-fA-F]{2}$/.test(raw.slice(at + 1, at + 3))
    ? parseInt(raw.slice(at + 1, at + 3), 16)
    : null);

  while (i < raw.length) {
    const lead = byteAt(i);
    if (lead !== null) {
      // ASCII는 %XX 하나가 한 글자, 그 외는 UTF-8 한 글자를 이루는 바이트만 묶는다
      let length = 1;
      if (lead >= 0xf0) length = 4;
      else if (lead >= 0xe0) length = 3;
      else if (lead >= 0xc0) length = 2;
      const j = i + length * 3;
      let decoded = null;
      try {
        decoded = decodeURIComponent(raw.slice(i, j));
      } catch {
        decoded = null;
      }
      if (decoded !== null && (length === 1 || decoded.length <= 2)) {
        for (let k = 0; k < decoded.length; k += 1) map.push([i, j]);
        text += decoded;
        i = j;
        continue;
      }
    }
    text += raw[i];
    map.push([i, i + 1]);
    i += 1;
  }

  return { text, map };
}

function findAll(haystack, needle) {
  const found = [];
  if (!needle) return found;
  const h = haystack.toLowerCase();
  const n = needle.toLowerCase();
  let at = h.indexOf(n);
  while (at !== -1) {
    found.push([at, at + n.length]);
    at = h.indexOf(n, at + n.length);
  }
  return found;
}

// 원문에서 먼저 찾고, 없으면 디코딩한 문자열에서 찾아 원문 위치로 되돌린다.
function locate(raw, needle) {
  const direct = findAll(raw, needle);
  if (direct.length) return direct;
  const { text, map } = decodeWithMap(raw);
  return findAll(text, needle).map(([s, e]) => [map[s][0], map[e - 1][1]]);
}

function splitEvidence(evidence) {
  if (!evidence) return [];
  return evidence
    .split(', ')
    .map((part) => part.replace(/×\d+$/, '').replace(/…$/, '').trim())
    .filter(Boolean);
}

function parseRawLog(rawLog) {
  try {
    const parsed = JSON.parse(rawLog);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

// 표시할 줄(요청 줄·본문·User-Agent)과 각 구간의 위치를 만든다.
export function buildRequestLines(log) {
  const raw = parseRawLog(log?.rawLog);
  const method = log?.requestMethod || raw.method || '';
  const url = log?.requestUrl || raw.path || '';
  const q = url.indexOf('?');
  const pathEnd = q === -1 ? url.length : q;
  const offset = method ? method.length + 1 : 0;
  const lastSegment = url.slice(0, pathEnd).split('/').pop();
  const dot = lastSegment.lastIndexOf('.');

  const request = {
    key: 'request',
    title: '요청',
    text: (method ? `${method} ` : '') + url,
    regions: {
      method: method ? [0, method.length] : null,
      path: [offset, offset + pathEnd],
      query: q === -1 ? null : [offset + q + 1, offset + url.length],
      url: [offset, offset + url.length],
      extension: dot > 0 ? [offset + pathEnd - (lastSegment.length - dot), offset + pathEnd] : null,
    },
  };

  const body = typeof raw.request_body === 'string' ? raw.request_body : '';
  const ua = typeof raw.http_user_agent === 'string' ? raw.http_user_agent : '';

  return [
    request,
    { key: 'body', title: '본문', text: body, regions: { body: body ? [0, body.length] : null } },
    { key: 'ua', title: 'User-Agent', text: ua, regions: { ua: ua ? [0, ua.length] : null } },
  ];
}

// 근거 표시 결과: 줄별 표시 구간(marks)과 범례(features).
export function buildEvidenceView(log, aiDescription) {
  const parsed = parseAiReason(aiDescription);
  if (!parsed.source) return null;

  const lines = buildRequestLines(log);
  const marks = Object.fromEntries(lines.map((line) => [line.key, []]));
  const features = parsed.items.map((item, index) => {
    const rank = index + 1;
    const { kind, region } = parsed.source === 'rule'
      ? { kind: 'pattern', region: 'all' }
      : classifyFeature(item.label);
    let placed = false;

    if (kind === 'pattern') {
      const needles = splitEvidence(item.evidence);
      lines.forEach((line) => {
        const scope = region === 'all' ? [0, line.text.length] : line.regions[region];
        if (!scope) return;
        const part = line.text.slice(scope[0], scope[1]);
        needles.forEach((needle) => {
          locate(part, needle).forEach(([s, e]) => {
            marks[line.key].push({ start: scope[0] + s, end: scope[0] + e, kind, rank });
            placed = true;
          });
        });
      });
    } else if (kind === 'range' || kind === 'compare') {
      lines.forEach((line) => {
        const scope = line.regions[region];
        if (scope && scope[1] > scope[0]) {
          marks[line.key].push({ start: scope[0], end: scope[1], kind, rank });
          placed = true;
        }
      });
    }

    return {
      rank,
      label: item.label,
      contribution: item.contribution,
      kind,
      caption: KIND_CAPTIONS[kind],
      placed: kind === 'absent' ? false : placed,
    };
  });

  const visibleLines = lines
    .filter((line) => line.key === 'request' || marks[line.key].length > 0)
    .map((line) => ({ ...line, segments: segment(line.text, marks[line.key]) }));

  return { source: parsed.source, review: parsed.review, rules: parsed.rules, lines: visibleLines, features };
}

// 글자마다 걸린 표시를 모아, 같은 표시가 이어지는 구간끼리 묶는다.
export function segment(text, marks) {
  const segments = [];
  let current = null;

  for (let i = 0; i < text.length; i += 1) {
    const covering = marks.filter((m) => m.start <= i && i < m.end);
    const pick = (kind) => {
      const ranks = covering.filter((m) => m.kind === kind).map((m) => m.rank);
      return ranks.length ? Math.min(...ranks) : null;
    };
    const style = { fill: pick('pattern'), range: pick('range'), compare: pick('compare') };
    const key = `${style.fill}|${style.range}|${style.compare}`;

    if (current && current.key === key) {
      current.text += text[i];
    } else {
      current = { key, text: text[i], ...style };
      segments.push(current);
    }
  }

  return segments;
}
