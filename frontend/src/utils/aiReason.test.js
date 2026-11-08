import { parseAiReason } from './aiReason';

describe('parseAiReason', () => {
  it('splits a model reason into ranked features with evidence and contribution', () => {
    const parsed = parseAiReason(
      '[모델] SQL 키워드 2개 [SELECT, FROM] +3.2 · URL 인코딩 문자 7개 [%20×5, %27×2] +2.1 · 처음 보는 경로·파라미터 조합 +1.5',
    );

    expect(parsed.source).toBe('model');
    expect(parsed.review).toBe(false);
    expect(parsed.rules).toEqual([]);
    expect(parsed.items).toEqual([
      { label: 'SQL 키워드 2개', evidence: 'SELECT, FROM', contribution: '+3.2' },
      { label: 'URL 인코딩 문자 7개', evidence: '%20×5, %27×2', contribution: '+2.1' },
      { label: '처음 보는 경로·파라미터 조합', evidence: null, contribution: '+1.5' },
    ]);
  });

  it('separates matched rules and the review flag from the feature list', () => {
    const parsed = parseAiReason(
      '[모델] XSS 패턴 1개 [<iframe] +1.8 · 규칙도 일치: UNION SELECT 구문, 공격 도구 User-Agent · 검토 권장: 구조 특성 위주 판정',
    );

    expect(parsed.items).toEqual([
      { label: 'XSS 패턴 1개', evidence: '<iframe', contribution: '+1.8' },
    ]);
    expect(parsed.rules).toEqual(['UNION SELECT 구문', '공격 도구 User-Agent']);
    expect(parsed.review).toBe(true);
  });

  it('keeps brackets inside evidence and parses rule reasons without contribution', () => {
    const parsed = parseAiReason(
      "[규칙] SQL 논리우회(OR/AND 토톨로지) [' OR 1=1] · XSS 패턴 [a]]>]",
    );

    expect(parsed.source).toBe('rule');
    expect(parsed.items).toEqual([
      { label: 'SQL 논리우회(OR/AND 토톨로지)', evidence: "' OR 1=1", contribution: null },
      { label: 'XSS 패턴', evidence: 'a]]>', contribution: null },
    ]);
  });

  it('falls back to the raw text for legacy or empty reasons', () => {
    expect(parseAiReason('SQL 논리우회(OR/AND 토톨로지)')).toEqual({
      source: null,
      items: [],
      rules: [],
      review: false,
      raw: 'SQL 논리우회(OR/AND 토톨로지)',
    });
    expect(parseAiReason(null).source).toBeNull();
  });
});
