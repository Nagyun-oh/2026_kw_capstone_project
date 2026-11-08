import { buildEvidenceView, classifyFeature, decodeWithMap } from './aiEvidence';

function marked(view, lineKey, field) {
  const line = view.lines.find((l) => l.key === lineKey);
  return line.segments.filter((s) => s[field] !== null).map((s) => s.text);
}

describe('classifyFeature', () => {
  it('maps feature labels to how they are drawn', () => {
    expect(classifyFeature('URL 인코딩 문자 2개')).toEqual({ kind: 'pattern', region: 'url' });
    expect(classifyFeature('처음 보는 경로·파라미터 조합')).toEqual({ kind: 'compare', region: 'url' });
    expect(classifyFeature('전체 길이 41자')).toEqual({ kind: 'range', region: 'url' });
    expect(classifyFeature('파라미터 0개')).toEqual({ kind: 'absent', region: 'query' });
    expect(classifyFeature('본문 없음')).toEqual({ kind: 'absent', region: 'body' });
    expect(classifyFeature('SQL 키워드 2개')).toEqual({ kind: 'pattern', region: 'all' });
  });

  it('keeps a zero count against the normal-traffic dictionary as a comparison', () => {
    expect(classifyFeature('정상 트래픽 경로 출현 0회')).toEqual({ kind: 'compare', region: 'path' });
  });
});

describe('decodeWithMap', () => {
  it('remembers the raw position of every decoded character', () => {
    const { text, map } = decodeWithMap('a%3Ciframe%3E+b');
    expect(text).toBe('a<iframe>+b');
    expect(map[1]).toEqual([1, 4]);
    expect(map[8]).toEqual([10, 13]);
  });

  it('maps each ASCII byte separately and groups multi-byte characters', () => {
    const { text, map } = decodeWithMap('%22%3E%ED%95%9C');
    expect(text).toBe('">한');
    expect(map).toEqual([[0, 3], [3, 6], [6, 15]]);
  });

  it('leaves broken percent sequences as they are', () => {
    expect(decodeWithMap('100%zz').text).toBe('100%zz');
    expect(decodeWithMap('%80x').text).toBe('%80x');
  });
});

describe('buildEvidenceView', () => {
  it('paints evidence, marks structural features and lists absent ones for a model decision', () => {
    const view = buildEvidenceView(
      { requestMethod: 'GET', requestUrl: '/rest/products/test%26sleep+15%26/reviews', rawLog: '{}' },
      '[모델] URL 인코딩 문자 2개 [%26×2] +1.9 · 처음 보는 경로·파라미터 조합 +1.6 · 파라미터 0개 +1.1 · 검토 권장: 구조 특성 위주 판정',
    );

    expect(view.review).toBe(true);
    expect(marked(view, 'request', 'fill')).toEqual(['%26', '%26']);
    expect(marked(view, 'request', 'compare').join('')).toBe('/rest/products/test%26sleep+15%26/reviews');
    expect(view.features.map((f) => [f.kind, f.placed])).toEqual([
      ['pattern', true],
      ['compare', true],
      ['absent', false],
    ]);
  });

  it('finds decoded evidence such as an encoded tag in the raw URL', () => {
    const view = buildEvidenceView(
      { requestMethod: 'PUT', requestUrl: '/rest/basket/3/coupon/%22%3E%3Ciframe%3E', rawLog: '{}' },
      '[모델] XSS 패턴 1개 [<iframe] +1.8',
    );

    expect(marked(view, 'request', 'fill')).toEqual(['%3Ciframe']);
  });

  it('paints rule evidence in the request body and the User-Agent', () => {
    const rawLog = JSON.stringify({
      request_body: '{"email":"\' OR 1=1--","password":"x"}',
      http_user_agent: 'sqlmap/1.8.4#stable',
    });
    const view = buildEvidenceView(
      { requestMethod: 'POST', requestUrl: '/rest/user/login', rawLog },
      "[규칙] SQL 논리우회(OR/AND 토톨로지) [' OR 1=1] · 공격 도구 User-Agent [sqlmap×2]",
    );

    expect(marked(view, 'body', 'fill')).toEqual(["' OR 1=1"]);
    expect(marked(view, 'ua', 'fill')).toEqual(['sqlmap']);
  });

  it('returns null for reasons it cannot read', () => {
    expect(buildEvidenceView({ requestUrl: '/' }, '-')).toBeNull();
  });
});
