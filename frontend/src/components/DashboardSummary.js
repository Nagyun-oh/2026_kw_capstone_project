const SUMMARY_CARDS = [
    {
        key: 'totalLogs',
        label: '저장된 로그',
        description: '현재 저장된 전체 로그',
        tone: 'primary',
    },
    {
        key: 'totalThreats',
        label: '위협 탐지 기록',
        description: '현재 저장된 전체 탐지 기록',
        tone: 'danger',
    },
    {
        key: 'totalBlacklistEntries',
        label: '차단 목록 등록',
        description: '실제 WAF 차단 여부와 별개인 등록 건수',
        tone: 'neutral',
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