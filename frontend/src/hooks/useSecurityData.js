import { useRef,useState } from 'react';
import apiClient from '../api/apiClient';

function useSecurityData() {

  /* == 검색 조건 상태 == */
  const EMPTY_LOG_SEARCH = {
    ip:"",
    method:"",
    statusCode:"",
  };

  const EMPTY_THREAT_SEARCH = {
    source: "",
    severity: "",
  };

  const EMPTY_BLACKLIST_SEARCH = {
    ip: "",
    severity: "",
  };

  const [logSearch,setLogSearch] = useState(EMPTY_LOG_SEARCH);
  const [threatSearch,setThreatSearch] = useState(EMPTY_THREAT_SEARCH);
  const [blacklistSearch,setBlacklistSearch] = useState(EMPTY_BLACKLIST_SEARCH);

  const [isThreatLoading, setIsThreatLoading] = useState(false);
  const [threatError,setThreatError] = useState('');
  const threatRequestIdRef = useRef(0);


  /* == 정보 및 페이지 상태 ( 전체 로그, 위협, 블랙리스트) == */
  const [logs, setLogs] = useState([]);
  const [logPage,setLogPage] = useState({
    number:0,
    totalPages:0,        // 전체 페이지 수
    totalElements:0,    // 전체 개수
    size:10,            // 한 페이지의 최대 데이터 개수
  });

  const [threats, setThreats] = useState([]);
  const [threatPage,setThreatPage] = useState({
    number:0,
    totalPages:0,
    totalElements:0,
    size:10,
  });

  const [blacklists, setBlacklists] = useState([]);
  const [blacklistPage,setBlackListPage] = useState({
    number:0,
    totalPages:0,
    totalElements:0,
    size:10,
  });
 
  /* == 조회 함수 ( 전체 로그, 위협, 블랙리스트) == */
  const fetchLogs = (page =0, search = logSearch) => {
    const params = {
      page,
      size:10
    };

    if(search.ip.trim()){
      params.ip = search.ip.trim();
    }

    if(search.method){
      params.method = search.method;
    }

    if(search.statusCode !== ""){
      params.statusCode = Number(search.statusCode);
    }

    apiClient.get(
      '/api/v1/logs',
      {params}
    )
    .then(response => {
      // 현재 페이지의 로그 목록 저장
      setLogs(response.data.content ?? []);

      // 백엔드 Page 응답의 페이지 정보 저장
      setLogPage({
        number: response.data.number,
        totalPages: response.data.totalPages,
        totalElements: response.data.totalElements,
        size: response.data.size,
      });
    })
    .catch(error =>{
      console.error("로그 조회 실패",error);
    });
  };

  const fetchLogById = async id => {
    const response = await apiClient.get(
      `/api/v1/logs/${id}`
    );

    return response.data;
  };

  const fetchThreats = async (page =0, search = threatSearch) => {
    const requestId = ++threatRequestIdRef.current;
    const params = {page, size:10};

    if(search.source){
      params.source = search.source;
    }

    if(search.severity){
      params.severity = search.severity;
    }

    setIsThreatLoading(true);
    setThreatError('');

    try{
      const response = await apiClient.get("api/v1/threats",{
        params,
      });

      // 이전 검색 응답이 현재 결과를 덮어 쓰지 않도록 한다.
      if(requestId !== threatRequestIdRef.current) return;

      setThreats(response.data.content??[]);

      setThreatPage({
        number: response.data.number,
        totalPages: response.data.totalPages,
        totalElements: response.data.totalElements,
        size: response.data.size,
      });
    
    } catch (error){
      if(requestId !== threatRequestIdRef.current) return;

      setThreats([]);
      setThreatPage({
        number: 0,
        totalPages: 0,
        totalElements: 0,
        size: 10,
      });

      if(error.response?.status === 401){
        setThreatError("로그인이 만료되었습니다. 다시 로그인해주세요.");
      }else if(error.response?.status === 400){
          setThreatError("검색 조건을 확인해주세요.");
      } else {
        setThreatError("위협 목록을 불러오지 못했습니다.")
      }

    } finally {
      if(requestId === threatRequestIdRef.current){
        setIsThreatLoading(false);
      }
    }
  };

  const fetchBlacklists = (page =0, search = blacklistSearch) => {
    const params = {page,size:10};

    if(search.ip.trim()){
      params.ip = search.ip.trim();
    }
    if(search.severity !== ""){
      params.severity = search.severity;
    }

    apiClient.get(
      '/api/v1/blacklist',
      {params}
    )
    .then(response => {
      // 현재 페이지의 로그 목록 저장
      setBlacklists(response.data.content ?? []);

      // 백엔드 Page 응답의 페이지 정보 저장
      setBlackListPage({
        number: response.data.number,
        totalPages: response.data.totalPages,
        totalElements: response.data.totalElements,
        size: response.data.size,
      });
    })
    .catch(error =>{
      console.error("블랙리스트 조회 실패",error);
    });
  };
  
  /* 전체 새로고침 */
  const fetchAllData = () => {
    fetchLogs(0);
    fetchThreats(0);
    fetchBlacklists(0);
  };

  /* 검색 적용 및 초기화 함수 */
  const searchLogs = condition => {
    setLogSearch(condition);
    fetchLogs(0,condition);
  }
  const resetLogSearch = () => {
    setLogSearch(EMPTY_LOG_SEARCH);
    fetchLogs(0,EMPTY_LOG_SEARCH);
  }

  const searchThreats = condition => {
    setThreatSearch(condition);
    fetchThreats(0,condition);
  };

  const resetThreatSearch = () => {
    setThreatSearch(EMPTY_THREAT_SEARCH);
    fetchThreats(0,EMPTY_THREAT_SEARCH);
  };

  const searchBlacklists = condition => {
    setBlacklistSearch(condition);
    fetchBlacklists(0,condition);
  };

  const resetBlacklistSearch= () => {
    setBlacklistSearch(EMPTY_BLACKLIST_SEARCH);
    fetchBlacklists(0,EMPTY_BLACKLIST_SEARCH);
  }


  /* 
    반환 객체
      사용하는 이유 : 커스텀 Hook 내부 값은 기본적으로 외부에서 접근 할 수 없음.
                      따라서, return에 포함해야 App.js에서 사용할 수 있음.
  */
  return { 
      logs, 
      logSearch,
      threats,
      blacklists, 
      logPage,
      threatPage,
      blacklistPage,
      fetchLogs,
      fetchThreats,
      fetchLogById,
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
  };
}

export default useSecurityData;

/* 
  useSecurityData.js : 서버 데이터와 페이지 상태 관리  
*/