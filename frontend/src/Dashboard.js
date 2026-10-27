import React, {useRef,useState} from 'react';
import {ToastContainer,toast} from 'react-toastify';  
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
import WafDetailModal from './components/WafDetailModal';
import BlacklistDeleteModal from './components/BlacklistDeleteModal';
import useWafSyncStatus from './hooks/useWafSyncStatus';
import WafSyncStatusPanel from './components/WafSyncStatusPanel';

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
      resetBlacklistSearch,
      isThreatLoading,
      threatError,
      deleteBlacklist,
      refreshBlacklists,
  } = useSecurityData();

  const {
    summary,
    isLoading: isSummaryLoading,
    errorMessage: summaryError,
    updatedAt: summaryUpdatedAt,
    refreshSummary,
  } = useDashboardSummary();

  const {
    data: wafSyncStatus,
    isLoading: isWafSyncLoading,
    errorMessage: wafSyncError,
    refreshWafStatus,
  } = useWafSyncStatus();

  const {isNewThreat, connectionStatus} 
    = useWebSocket (() => {
    fetchThreats(0);
    fetchBlacklists(0);
  });

  const [isLogModalOpen, setIsLogModalOpen] = useState(false);
  const [selectedLog,setSelectedLog] = useState(null);
  const [isLogLoading,setIsLogLoading] = useState(false);
  const [logDetailError,setLogDetailError] = useState('');
  const [selectedWafThreatId, setSelectedWafThreatId] = useState(null);
  
  const [deletingBlacklistId, setDeletingBlacklistId] = useState(null);

  const [blacklistToDelete, setBlacklistToDelete] = useState(null);
  const [blacklistDeleteError, setBlacklistDeleteError] = useState(''); 

  // 연속 클릭으로 삭제 요청이 중복 실행되지 않도록 한다.
  const blacklistDeleteInFlightRef = useRef(false);

  // 가장 최근 상세 조회 요청을 구분하는 번호
  const logRequestIdRef = useRef(0);

  const handleViewLog = async logId => {
    setSelectedWafThreatId(null);

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

const handleViewWaf = threatId => {
  handleCloseLogModal();
  setSelectedWafThreatId(threatId);
}

function handleRefreshAll(){
  fetchAllData();
  refreshSummary();
  refreshWafStatus();
}

// 목록의 삭제 버튼: 확인 모달을 연다.
const handleDeleteBlacklist = entry => {
  if (blacklistDeleteInFlightRef.current) return;

  setBlacklistDeleteError('');
  setBlacklistToDelete(entry);
};

// 취소 버튼 또는 Escape: 확인 모달을 닫는다.
const handleCloseBlacklistDelete = () => {
  if (blacklistDeleteInFlightRef.current) return;

  setBlacklistToDelete(null);
  setBlacklistDeleteError('');
};

// 모달의 삭제하기 버튼: 실제 삭제 요청을 보낸다.
const handleConfirmBlacklistDelete = async () => {
  if (!blacklistToDelete || blacklistDeleteInFlightRef.current) {
    return;
  }

  const entry = blacklistToDelete;

  blacklistDeleteInFlightRef.current = true;
  setDeletingBlacklistId(entry.id);
  setBlacklistDeleteError('');

  try {
    try {
      await deleteBlacklist(entry.id);

      setBlacklistToDelete(null);
      toast.success(
        `${entry.ipAddress}를 블랙리스트에서 삭제했습니다.`
      );
    } catch (error) {
      const status = error.response?.status;

      if (status === 404) {
        setBlacklistToDelete(null);
        toast.info(
          '이미 삭제되었거나 존재하지 않는 항목입니다. 목록을 갱신합니다.'
        );
      } else {
        if (status === 401) {
          setBlacklistDeleteError(
            '로그인이 만료되었습니다. 창을 닫고 다시 로그인해주세요.'
          );
        } else if (status === 403) {
          setBlacklistDeleteError(
            '삭제 권한 또는 CSRF 인증을 확인하지 못했습니다. 다시 로그인한 뒤 시도해주세요.'
          );
        } else {
          setBlacklistDeleteError(
            '삭제 요청을 완료하지 못했습니다. 창을 닫고 목록을 새로고침해 확인해주세요.'
          );
        }

        return;
      }
    }

    const [listUpdated] = await Promise.all([
      refreshBlacklists(),
      refreshSummary(),
      refreshWafStatus(),
    ]);

    if (listUpdated === false) {
      toast.warning(
        '삭제 대상은 목록에서 제거되었지만 화면 목록을 갱신하지 못했습니다. 전체 데이터 새로고침을 눌러주세요.'
      );
    }
  } finally {
    blacklistDeleteInFlightRef.current = false;
    setDeletingBlacklistId(null);
  }
};

 return (
     <DashboardLayout
      user = {user}
      connectionStatus={connectionStatus}
      onLogout={onLogout}
      isLoggingOut={isLoggingOut}
      logoutError={logoutError}
     >

      <ToastContainer />

      <BlacklistDeleteModal
      entry={blacklistToDelete}
      busy={deletingBlacklistId != null}
      error={blacklistDeleteError}
      onClose={handleCloseBlacklistDelete}
      onConfirm={handleConfirmBlacklistDelete}
      />

      <LogDetailModal 
        isOpen={isLogModalOpen}
        log={selectedLog}
        loading={isLogLoading}
        error={logDetailError}
        onClose={handleCloseLogModal}
      />

      <WafDetailModal
        threatId={selectedWafThreatId}
        onClose={() => setSelectedWafThreatId(null)}
        onViewLog={handleViewLog}
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
        loading = {isThreatLoading}
        error = {threatError}
        onPageChange={fetchThreats}
        onSearch={searchThreats}
        onReset={resetThreatSearch}
        onViewLog={handleViewLog}
        onViewWaf={handleViewWaf}
      />
    </div>

    <div id="security-blacklist" className="dashboard-section">
      <WafSyncStatusPanel
        data={wafSyncStatus}
        isLoading={isWafSyncLoading}
        errorMessage={wafSyncError}
        onRefresh={refreshWafStatus}
      />
      <BlacklistTable
        blacklists={blacklists}
        pageInfo={blacklistPage}
        onPageChange={fetchBlacklists}
        onSearch={searchBlacklists}
        onReset={resetBlacklistSearch}
        onViewLog={handleViewLog}
        onDelete={handleDeleteBlacklist}
        deletingId={deletingBlacklistId}
      />
    </div>
     </DashboardLayout>
  );
}

export default Dashboard;