const SUMMARY_CARDS = [
    {
        key: 'totalLogs',
        label: '저장된 로그',
        description: '현재 저장된 전체 로그',
        tone: 'neutral',
    },
    {
        key: 'totalThreats',
        label: '통합 위협 기록',
        description: '같은 요청의 WAF·AI 탐지를 통합한 기록',
        tone: 'primary',
    },
    {
        key: 'totalBlacklistEntries',
        label: '차단 목록 등록',
        description: 'IP 차단',
        tone: 'danger',
    },
];


function DashboardSummary({
    summary,
    isLoading,
    errorMessage,
    updatedAt,
}){
    const hasData = summary !=null;

    return (
        <section className="dashboard-summary" aria-label="전체 데이터 요약">
            <div className="dashboard-summary__heading">
            <h2>전체 현황</h2>

            <p role="status">
                {isLoading
                    ? '요약 정보 조회 중...'
                    : updatedAt
                        ? `최근 조회 ${updatedAt.toLocaleTimeString('ko-kr',
                            {timeZone: 'Asia/Seoul',}
                        )}`
                        : `조회된 정보 없음`}
            </p>
            </div>

            {errorMessage && (
                <p className="dashboard-error" role="alert">
                    {errorMessage}
                    {hasData && ' 아래 수치는 이전 조회 결과입니다.'}
                </p>
            )}

            <div className="summary-grid" aria-busy={isLoading}>
                {SUMMARY_CARDS.map(card =>(
                    <article
                        key={card.key}
                        className={`summary-card summary-card--${card.tone}`}
                    >
                        <h3 className="summary-card__label">{card.label}</h3>

                        <p className="summary-card__value">
                            {hasData
                                ? summary[card.key].toLocaleString('ko-KR')
                                :'-' }

                            {hasData && (
                                <span className="summary-card__unit">건</span>
                            )}
                        </p>

                        <p className="summary-card__description">
                            {card.description}
                        </p>
                    </article>
                ))}
            </div>
            
            <p className ="dashboard-summary__note">
                목록 검색 조건과 무관한 조회 시점의 전체 건수입니다.
            </p>
        </section>
    );
}

export default DashboardSummary;