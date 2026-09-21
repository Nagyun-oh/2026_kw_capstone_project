import { useState } from 'react';
import axios from 'axios';
import {API_BASE_URL} from '../config';

function useSecurityData() {

  /* == 검색 조건 상태 == */
  const EMPTY_LOG_SEARCH = {
    ip:"",
    method:"",
    statusCode:"",
  };

  const EMPTY_THREAT_SEARCH = {
    threatType: "",
    severity: "",
  };

  const EMPTY_BLACKLIST_SEARCH = {
    ip: "",
    dangerLevel: "",
  };

  const [logSearch,setLogSearch] = useState(EMPTY_LOG_SEARCH);
  const [threatSearch,setThreatSearch] = useState(EMPTY_THREAT_SEARCH);
  const [blacklistSearch,setBlacklistSearch] = useState(EMPTY_BLACKLIST_SEARCH);


  /* == 정보 및 페이지 상태 ( 전체 로그, 위협, 블랙리스트) == */
  const [logs, setLogs] = useState([]);
  const [logPage,setLogPage] = useState({
    number:0,
    totalPages:0,        // 전체 페이지 수
    totalElements:0,    // 전체 개수
    size:20,            // 한 페이지의 최대 데이터 개수
  });

  const [threats, setThreats] = useState([]);
  const [threatPage,setThreatPage] = useState({
    number:0,
    totalPages:0,
    totalElements:0,
    size:20,
  });

  const [blacklists, setBlacklists] = useState([]);
  const [blacklistPage,setBlackListPage] = useState({
    number:0,
    totalPages:0,
    totalElements:0,
    size:20,
  });
 
  /* == 조회 함수 ( 전체 로그, 위협, 블랙리스트) == */
  const fetchLogs = (page =0, search = logSearch) => {
    const params = {
      page,
      size:20
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

    axios.get(
      `${API_BASE_URL}/api/v1/logs`,
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
    const response = await axios.get(
      `${API_BASE_URL}/api/v1/logs/${id}`
    );

    return response.data;
  };

  const fetchThreats = (page =0, search = threatSearch) => {
    const params = {page, size:20};

    if(search.threatType.trim()){
      params.threatType = search.threatType.trim();
    }

    if(search.severity){
      params.severity = search.severity;
    }

    axios.get(
      `${API_BASE_URL}/api/v1/threats`,
      {params}
    )
    .then(response => {
      // 현재 페이지의 로그 목록 저장
      setThreats(response.data.content ?? []);

      // 백엔드 Page 응답의 페이지 정보 저장
      setThreatPage({
        number: response.data.number,
        totalPages: response.data.totalPages,
        totalElements: response.data.totalElements,
        size: response.data.size,
      });
    })
    .catch(error =>{
      console.error("위협 조회 실패",error);
    });
  };

  const fetchBlacklists = (page =0, search = blacklistSearch) => {
    const params = {page,size:20};

    if(search.ip.trim()){
      params.ip = search.ip.trim();
    }
    if(search.dangerLevel !== ""){
      params.dangerLevel = Number(search.dangerLevel);
    }

    axios.get(
      `${API_BASE_URL}/api/v1/blacklist`,
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
  };
}

export default useSecurityData;

/* 
  useSecurityData.js : 서버 데이터와 페이지 상태 관리  
*/