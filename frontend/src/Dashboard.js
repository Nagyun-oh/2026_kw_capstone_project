import React, {useRef,useState} from 'react';
import {ToastContainer} from 'react-toastify';  
import 'react-toastify/dist/ReactToastify.css';

import ThreatTable from './components/ThreatTable';
import BlacklistTable from './components/BlacklistTable';
import LogTable from './components/LogTable';
import useSecurityData from './hooks/useSecurityData';
import useWebSocket from './hooks/useWebSocket';
import LogDetailModal from './components/LogDetailModal';
import DashboardLayout from './components/DashboardLayout';
import DashboardSummary from './components/DashboardSummary';
import useDashboardSummary from './hooks/useDashboardSummary';

function Dashboard({
  user,
  onLogout,
  isLoggingOut,
  logoutError,
}) {
 
  const { 
      logs, 
      threats,
      blacklists, 
      logPage,
      threatPage,
      blacklistPage,
      fetchLogs,
      fetchLogById,
      fetchThreats,
      fetchBlacklists,
      fetchAllData, 
      searchLogs,
      resetLogSearch,
      searchThreats,
      resetThreatSearch,
      searchBlacklists,
      resetBlacklistSearch
  } = useSecurityData();

  const {
    summary,
    isLoading: isSummaryLoading,
    errorMessage: summaryError,
    updatedAt: summaryUpdatedAt,
    refreshSummary,
  } = useDashboardSummary();

  const {isNewThreat, connectionStatus} 
    = useWebSocket (() => {
    fetchThreats(0);
    fetchBlacklists(0);
  });

  const [isLogModalOpen, setIsLogModalOpen] = useState(false);
  const [selectedLog,setSelectedLog] = useState(null);
  const [isLogLoading,setIsLogLoading] = useState(false);
  const [logDetailError,setLogDetailError] = useState('');

  // 가장 최근 상세 조회 요청을 구분하는 번호
  const logRequestIdRef = useRef(0);

  const handleViewLog = async logId => {
    // 새 요청마다 번호 증가
    const requestId = ++logRequestIdRef.current;

  setIsLogModalOpen(true);
  setSelectedLog(null);
  setLogDetailError('');
  setIsLogLoading(true);

  try {
    const log = await fetchLogById(logId);

    // 이후 다른 로그를 열었거나 모달을 닫았다면 무시
    if(requestId !== logRequestIdRef.current)return;

    setSelectedLog(log);
  } catch (error) {
    // 이전 요청의 오류가 현재 모달에 표시되지 않도록 처리
    if(requestId !== logRequestIdRef.current) return;

    console.error('로그 상세 조회 실패', error);

    if (error.response?.status === 404) {
      setLogDetailError('해당 원본 로그를 찾을 수 없습니다.');
    } else {
      setLogDetailError('로그 상세 정보를 불러오지 못했습니다.');
    }
  } finally {
    // 이전 요청이 현재 요청의 로딩 표시를 종료하지 않도록 처리
    if(requestId === logRequestIdRef.current){
      setIsLogLoading(false);
    }
  }
};

const handleCloseLogModal = () => {
  // 진행 중인 요청의 응답을 더 이상 반영하지 않음
  logRequestIdRef.current +=1;

  setIsLogModalOpen(false);
  setSelectedLog(null);
  setLogDetailError('');
};

function handleRefreshAll(){
  fetchAllData();
  refreshSummary();
}

 return (
     <DashboardLayout
      user = {user}
      connectionStatus={connectionStatus}
      onLogout={onLogout}
      isLoggingOut={isLoggingOut}
      logoutError={logoutError}
     >

      <ToastContainer />

      <LogDetailModal 
        isOpen={isLogModalOpen}
        log={selectedLog}
        loading={isLogLoading}
        error={logDetailError}
        onClose={handleCloseLogModal}
      />

      <div className="dashboard-toolbar">
        <button
          type="button"
          className='dashboard-button dashboard-button--primary'
          onClick={handleRefreshAll}
        >
          전체 데이터 새로고침
        </button>
      </div>

    <DashboardSummary
      summary={summary}
      isLoading={isSummaryLoading}
      errorMessage={summaryError}
      updatedAt={summaryUpdatedAt}
    >
    </DashboardSummary>


      <div id="security-logs" className="dashboard-section">
      <LogTable
        logs={logs}
        pageInfo={logPage}
        onPageChange={fetchLogs}
        onSearch={searchLogs}
        onReset={resetLogSearch}
        onViewLog = {handleViewLog}
      >
      </LogTable>
      </div>

      <div id="security-threats" className="dashboard-section">
      <ThreatTable
        threats={threats}
        isNewThreat={isNewThreat}
        pageInfo={threatPage}
        onPageChange={fetchThreats}
        onSearch={searchThreats}
        onReset={resetThreatSearch}
        onViewLog={handleViewLog}
      />
    </div>

    <div id="security-blacklist" className="dashboard-section">
      <BlacklistTable
        blacklists={blacklists}
        pageInfo={blacklistPage}
        onPageChange={fetchBlacklists}
        onSearch={searchBlacklists}
        onReset={resetBlacklistSearch}
        onViewLog={handleViewLog}
      />
    </div>
     </DashboardLayout>
  );
}

export default Dashboard;