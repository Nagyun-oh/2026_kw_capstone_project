import '../styles/dashboard.css';

const CONNECTION_STATUS = {

    connected: {
        label: '실시간 알림 연결됨',
        tone: 'success',
    },
    connecting: {
        label: '실시간 알림 연결 중',
        tone: 'pending',
    },
    reconnecting:{
        label: '실시간 알림 재연결 중',
        tone: 'pending',
    },
    error: {
        label: '실시간 알림 연결 오류',
        tone: 'error',
    },
};

function DashboardLayout({
    user,
    connectionStatus,
    onLogout,
    isLoggingOut,
    logoutError,
    children,
}) {
    const connection = 
        CONNECTION_STATUS[connectionStatus] ?? CONNECTION_STATUS.error;

    return (
        <div className="dashboard-layout" id="dashboard-overview">
            <aside className="dashboard-sidebar">
                <a className="dashboard-brand" href="#dashboard-overview">
                    <span className="dashboard-brand__mark" aria-hidden="true">
                        S
                    </span>

                    <span>
                        <strong>Security Monitor</strong>
                        <small>보안 위협 분석 시스템</small>
                    </span>
                </a>

                <p className="dashboard-sidebar__label">모니터링</p>

                <nav className="dashboard-nav" aria-label="대시보드 메뉴">
                    <a href="#dashboard-overview">대시보드</a>
                    <a href="#security-logs">전체 로그</a>
                    <a href="#security-threats">위협 탐지</a>
                    <a href="#security-blacklist">차단 목록 IP</a>
                </nav>

                <div className="dashboard-sidebar__footer">
                    관리자 전용 대시보드
                </div>
            </aside>

            <div className="dashboard-workspace">
                <header className="dashboard-header">
                    <div>
                        <p className="dashboard-eyebrow">SECURITY MONITORING</p>
                        <h1>대시보드</h1>
                        <p className="dashboard-description">
                            수집된 로그와 탐지된 보안 위협을 확인하세요.
                        </p>
                    </div>

                    <div className="dashboard-header__actions">
                        <span
                            className={`connection-badge connection-badge--${connection.tone}`}
                            role="status"
                        >
                            <span className="connection-badge__dot" aria-hidden="true"/>
                            {connection.label}
                        </span>

                        <span className="dashboard-user">
                            {user.username}님
                        </span>

                        <button
                            type="button"
                            className="dashboard-button dashboard-button--secondary"
                            onClick={onLogout}
                            disabled={isLoggingOut}
                        >
                            {isLoggingOut ? '로그아웃 중...': '로그아웃'}
                        </button>
                    </div>
                </header>

                <main className="dashboard-content">
                    {logoutError &&(
                        <p className="dashboard-error" role="alert">
                            {logoutError}
                        </p>
                    )}

                    {children}
                </main>
            </div>
        </div>
    );
}

export default DashboardLayout;