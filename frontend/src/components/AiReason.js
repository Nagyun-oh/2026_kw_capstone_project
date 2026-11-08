import { parseAiReason } from '../utils/aiReason';

const SOURCE_LABELS = {
  model: '모델 판정',
  rule: '규칙 판정',
};

// 위협 탐지 표의 AI 탐지 설명. 판정 출처 배지와 근거를 한 줄씩 나눠 보여 준다.
function AiReason({ text }) {
  const parsed = parseAiReason(text);

  if (!parsed.raw) {
    return '—';
  }

  if (!parsed.source) {
    return parsed.raw;
  }

  return (
    <div className="ai-reason" title={parsed.raw}>
      <div className="ai-reason__badges">
        <span className={`data-badge data-badge--${parsed.source === 'model' ? 'info' : 'neutral'}`}>
          {SOURCE_LABELS[parsed.source]}
        </span>

        {parsed.review && (
          <span className="data-badge data-badge--warning">검토 권장</span>
        )}
      </div>

      <ol className="ai-reason__list">
        {parsed.items.map((item, index) => (
          <li className="ai-reason__item" key={`${index}-${item.label}`}>
            <div className="ai-reason__row">
              <span className="ai-reason__label">{item.label}</span>
              {item.contribution && (
                <span className="ai-reason__score">{item.contribution}</span>
              )}
            </div>

            {item.evidence && (
              <code className="ai-reason__evidence">{item.evidence}</code>
            )}
          </li>
        ))}
      </ol>

      {parsed.rules.length > 0 && (
        <p className="ai-reason__rules">
          규칙도 일치: {parsed.rules.join(', ')}
        </p>
      )}
    </div>
  );
}

export default AiReason;
