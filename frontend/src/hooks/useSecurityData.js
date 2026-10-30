import { useEffect,useRef,useState } from 'react';
import apiClient from '../api/apiClient';

function useSecurityData() {

  /* == 검색 조건 상태 == */
  const EMPTY_LOG_SEARCH = {
    logId:"",
    ip:"",
    method:"",
    statusCode:"",
  };

  const EMPTY_THREAT_SEARCH = {
    threatId: "",
    source: "",
    severity: "",
  };

  const EMPTY_BLACKLIST_SEARCH = {
    ip: "",
    severity: "",
  };

  const [logSearch,setLogSearch] = useState(EMPTY_LOG_SEARCH);

  // 가장 최근 목록 조회와 적용된 검색 조건을 기억한다.
  const blacklistRequestIdRef = useRef(0);
  const blacklistSearchRef = useRef(EMPTY_BLACKLIST_SEARCH);

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

  // 마지막으로 요청한 검색 조건과 페이지
  const logQueryRef = useRef({
    page:0,
    search: EMPTY_LOG_SEARCH,
  });

  const threatQueryRef = useRef({
    page:0,
    search: EMPTY_THREAT_SEARCH,
  });

  const blacklistQueryRef = useRef({
    page:0,
    search: EMPTY_BLACKLIST_SEARCH,
  });

  // 자동 조회가 진행 중인 요청과 겹치지 않도록 한다.
  const logBusyRef = useRef(false);
  const threatBusyRef = useRef(false);
  const blacklistBusyRef = useRef(false);

  // 로그 목록에도 오래된 응답 방지 적용
  const logRequestIdRef = useRef(0);

  const [logError,setLogError] = useState('');
  const [blacklistError,setBlacklistError] = useState('');

  /* == 조회 함수 ( 전체 로그, 위협, 블랙리스트) == */
  const fetchLogs =  async (
    page = 0,
    search = logQueryRef.current.search,
    { background = false} = {}
   ) => {
    
    // 백그라운드 중복 요청방지
    if (background && logBusyRef.current){
      return null;
    }

    // 요청 번호와 조회 조건 기록
    const requestId = ++logRequestIdRef.current;

    // 요청 중임을 기록하고, 이번에 요청하는 페이지와 검색 조건을 저장
    logBusyRef.current = true;
    logQueryRef.current = {
      page,
      search: {...search},
    };

    // 일반 조회시 기존 오류 메시지 지우기
    if(!background){
      setLogError('');
    }

    // 검색 파라미터 설정
    const params = {page,size:10};
    const logId = String(search.logId?? '').trim();  // Long ID가 JS number 변환으로 변형되지 않게 문자열로 전달

    if(logId){
      params.logId = logId;
    }

    if(search.ip.trim()){
      params.ip = search.ip.trim();
    }

    if (search.method) {
      params.method = search.method;
    }

    if (search.statusCode !== '') {
      params.statusCode = Number(search.statusCode);
    }

    try {
      
      // 검색 조건을 쿼리 파라미터로 전달해서 GET 요청을 보내고 응답을 기다림
      const response = await apiClient.get('/api/v1/logs',{
        params,
      })

      if(requestId !== logRequestIdRef.current){
        return null;
      }

      setLogs(response.data.content ?? []);

      setLogPage({
        number: response.data.number,
        totalPages: response.data.totalPages,
        totalElements: response.data.totalElements,
        size: response.data.size,
      });

      setLogError('');
      return true;
    } catch (error){
      if(requestId !== logRequestIdRef.current){
        return null;
      }

      const status = error.response?.status;

      setLogError(
        status ===401
          ? '로그인이 만료되었습니다. 다시 로그인해주세요.'
          : status === 400
          ? '로그 검색 조건을 확인해주세요.'
          : '로그 목록을 갱신하지 못했습니다.'
      );

      // 마지막으로 성공한 목록은 유지
      return false;
    } finally {
      if(requestId === logRequestIdRef.current){
        logBusyRef.current = false;
      }
    }
   };

  const fetchLogById = async id => {
  const response = await apiClient.get(`/api/v1/logs/${id}`);

    return response.data;
   };

  const fetchThreats = async (
    page =0, 
    search = threatQueryRef.current.search,
    {background = false} = {}
  ) => {

    if(background && threatBusyRef.current){
      return null;
    }

    const requestId = ++threatRequestIdRef.current;

    // 요청 중임을 기록하고, 이번에 요청하는 페이지와 검색 조건을 저장
    threatBusyRef.current = true;
    threatQueryRef.current = {
      page,
      search: {...search},
    };

    const params = {page, size:10};

    const threatId = String(search.threatId ?? '').trim();

    if(threatId){
      params.threatId = threatId;
    }

    if(search.source){
      params.source = search.source;
    }

    if(search.severity){
      params.severity = search.severity;
    }

    if(!background){
      setIsThreatLoading(true);
      setThreatError('');
    }
    
    try{
      const response = await apiClient.get("api/v1/threats/grouped",{
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

      setThreatError('');
      return true;
    
    } catch (error){
      if(requestId !== threatRequestIdRef.current) return;

      if(!background){
        setThreats([]);

        setThreatPage({
          number: 0,
          totalPages: 0,
          totalElements: 0,
          size: 10,
        });
    }

      if(error.response?.status === 401){
        setThreatError("로그인이 만료되었습니다. 다시 로그인해주세요.");
      }else if(error.response?.status === 400){
          setThreatError("검색 조건을 확인해주세요.");
      } else {
        setThreatError("위협 목록을 불러오지 못했습니다.")
      }

      return false;

    } finally {
      if(requestId === threatRequestIdRef.current){
        threatBusyRef.current = false;
        setIsThreatLoading(false);
      }
    }
  };

  const fetchBlacklists = async (
    page =0, 
    search = blacklistQueryRef.current.search,
    {background = false} = {}
  ) => {

    if (background && blacklistBusyRef.current) {
      return null;
    }

    const requestId = ++blacklistRequestIdRef.current;

    blacklistBusyRef.current = true;

    blacklistQueryRef.current = {
      page,
      search: {...search},
    };

    blacklistSearchRef.current = {...search};

    if(!background){
      setBlacklistError('');
    }

    const params = {page,size:10};

    if(search.ip.trim()){
      params.ip = search.ip.trim();
    }
    if(search.severity !== ""){
      params.severity = search.severity;
    }

    try {
      const response = await apiClient.get('/api/v1/blacklist',{
        params,
      });

      // 오래된 조회 결과가 최신 목록을 덮어쓰지 않도록 한다.
      if(requestId !== blacklistRequestIdRef.current){
        return null;
      }

      // 현재 페이지의 로그 목록 저장
       setBlacklists(response.data.content ?? []);

        // 백엔드 Page 응답의 페이지 정보 저장
        setBlackListPage({
        number: response.data.number,
        totalPages: response.data.totalPages,
        totalElements: response.data.totalElements,
        size: response.data.size,
      });

      setBlacklistError('');

      return true;
    } catch (error){
      if(requestId !== blacklistRequestIdRef.current){
        return null;
      }

      console.error('블랙리스트 조회 실패',error);
      setBlacklistError(
        error.response?.status === 401
        ? '로그인이 만료되었습니다. 다시 로그인해주세요.'
        : '블랙리스트 목록을 갱신하지 못했습니다.'
      );

      return false;
    } finally{
      if(requestId === blacklistRequestIdRef.current){
        blacklistBusyRef.current = false;
      }
    }
  };

  // 삭제 실패는 호출한 Dashbaord에서 처리한다
  const deleteBlacklist = async id => {
    await apiClient.delete(`/api/v1/blacklist/${id}`);
  };

  // 현재 적용된 검색 조건으로 첫 페이지를 다시 조회한다.
  const refreshBlacklists = () => {
    return fetchBlacklists(0,blacklistSearchRef.current);
  }
  
  // 현재 검색 조건과 페이지를 유지해서 다시 조회한다.
  const fetchAllData = ({background = false} = {}) => {
   return Promise.all([
    fetchLogs(
      logQueryRef.current.page,
      logQueryRef.current.search,
      {background}
    ),

    fetchThreats(
      threatQueryRef.current.page,
      threatQueryRef.current.search,
      {background}
    ),

    fetchBlacklists(
      blacklistQueryRef.current.page,
      blacklistQueryRef.current.search,
      {background}
    ),
   ]);
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
    fetchThreats(0,condition);
  };

  const resetThreatSearch = () => {
    fetchThreats(0,EMPTY_THREAT_SEARCH);
  };

  const searchBlacklists = condition => {
    fetchBlacklists(0,condition);
  };

  const resetBlacklistSearch= () => {
    fetchBlacklists(0,EMPTY_BLACKLIST_SEARCH);
  }

  const addBlacklist = async request => {
    await apiClient.post('/api/v1/blacklist',request);
  };

  useEffect(() => {
    return() => {
      logRequestIdRef.current +=1;
      threatRequestIdRef.current +=1;
      blacklistRequestIdRef.current +=1;

      logBusyRef.current = false;
      threatBusyRef.current = false;
      blacklistBusyRef.current = false;
    };
  },[]);

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
      deleteBlacklist,
      refreshBlacklists,
      addBlacklist,
      logError,
      blacklistError,
  };
}

export default useSecurityData;

/* 
  useSecurityData.js : 서버 데이터와 페이지 상태 관리  
*/