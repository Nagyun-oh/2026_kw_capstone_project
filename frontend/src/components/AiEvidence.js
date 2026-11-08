import { buildEvidenceView } from '../utils/aiEvidence';

const SOURCE_LABELS = {
  model: '모델 판정',
  rule: '규칙 판정',
};

function segmentClass(segment) {
  const classes = ['ai-evidence__mark'];
  if (segment.fill) classes.push(`ai-evidence__fill--${segment.fill}`);
  if (segment.range) classes.push(`ai-evidence__range--${segment.range}`);
  if (segment.compare) classes.push(`ai-evidence__compare--${segment.compare}`);
  return classes.join(' ');
}

// 위협 탐지에서 연 로그 상세에 AI 판정 근거의 위치를 원본 요청 위에 표시한다.
// 모양은 피처 종류(색칠·밑줄·점선·없음), 색은 기여도 순위(1·2·3위)를 뜻한다.
function AiEvidence({ log, aiDescription }) {
  const view = buildEvidenceView(log, aiDescription);

  if (!view || view.features.length === 0) {
    return null;
  }

  const absent = view.features.filter((feature) => feature.kind === 'absent');

  return (
    <section className="log-detail-section">
      <h3>AI 판정 근거 위치</h3>

      <p className="log-detail-help">
        판정에 기여한 피처가 가리키는 위치입니다. 글자 단위 기여도가 아니며,
        오른쪽 숫자는 판정을 공격 쪽으로 기울게 한 정도입니다.
      </p>

      <div className="ai-reason__badges">
        <span className={`data-badge data-badge--${view.source === 'model' ? 'info' : 'neutral'}`}>
          {SOURCE_LABELS[view.source]}
        </span>
        {view.review && (
          <span className="data-badge data-badge--warning">검토 권장</span>
        )}
      </div>

      <div className="ai-evidence__request">
        {view.lines.map((line) => (
          <div className="ai-evidence__line" key={line.key}>
            <span className="ai-evidence__line-title">{line.title}</span>
            <code className="ai-evidence__text">
              {line.segments.length === 0 && <span className="data-muted">(없음)</span>}
              {line.segments.map((segment, index) => (
                segment.fill || segment.range || segment.compare ? (
                  <mark className={segmentClass(segment)} key={index}>{segment.text}</mark>
                ) : (
                  <span key={index}>{segment.text}</span>
                )
              ))}
            </code>
          </div>
        ))}

        {absent.length > 0 && (
          <div className="ai-evidence__line">
            <span className="ai-evidence__line-title">없는 항목</span>
            <div className="ai-evidence__absent-list">
              {absent.map((feature) => (
                <span
                  className={`ai-evidence__absent ai-evidence__absent--${feature.rank}`}
                  key={feature.rank}
                >
                  ∅ {feature.label}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      <ol className="ai-evidence__legend">
        {view.features.map((feature) => (
          <li className="ai-evidence__legend-item" key={feature.rank}>
            <span
              className={`ai-evidence__swatch ai-evidence__swatch--${feature.kind} ai-evidence__swatch--rank-${feature.rank}`}
              aria-hidden="true"
            />
            <span className="ai-evidence__legend-text">
              <span className="ai-reason__row">
                <span className="ai-reason__label">{feature.label}</span>
                {feature.contribution && (
                  <span className="ai-reason__score">{feature.contribution}</span>
                )}
              </span>
              <span className="ai-evidence__caption">
                {feature.caption}
                {!feature.placed && feature.kind !== 'absent' && ' · 요청에서 위치를 찾지 못함'}
              </span>
            </span>
          </li>
        ))}
      </ol>

      {view.rules.length > 0 && (
        <p className="ai-reason__rules">규칙도 일치: {view.rules.join(', ')}</p>
      )}
    </section>
  );
}

export default AiEvidence;
