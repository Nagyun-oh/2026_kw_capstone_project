import {useEffect,useState } from "react";
import {
    getCurrentAdmin,
    loginAdmin,
    logoutAdmin,
} from '../api/authAPI';
import apiClient from "../api/apiClient";

function useAuth(){
    const [user,setUser] = useState(null);                  // 로그인한 사용자 정보, 없으면 null
    const [status,setStatus] = useState('loading');         // 확인 중·로그인됨·비로그인·권한 없음·오류
    const [errorMessage, setErrorMessage] = useState('');   // 화면에 보여줄 조회 오류 메시지
    const [checkVersion,setCheckVersion] = useState(0);     // 로그인 상태 재조회 실행을 위한 숫자

    // 처음 화면에 들어왔을 때 로그인 확인
    useEffect(() =>{
        let ignore = false;

        async function checkSession(){
            setStatus('loading');
            setErrorMessage('');
            setUser(null);

            try{
                const currentUser = await getCurrentAdmin();

                if(ignore) return;

                if(currentUser.role !== 'ROLE_ADMIN'){
                    setStatus('forbidden');
                    return;
                }

                setUser(currentUser);
                setStatus('authenticated');
            } catch (error) {
                if(ignore) return;

                const httpStatus = error.response?.status;

                if(httpStatus === 401){
                    setStatus('anonymous');
                }else if(httpStatus === 403){
                    setStatus('forbidden');
                } else {
                    setStatus('error');
                    setErrorMessage('로그인 상태를 확인하지 못했습니다. 잠시 후 다시 시도해주세요.');
                }
            }
        }

        checkSession();

        return () => {
            ignore = true;
        };

    }, [checkVersion]);

    // 로그인 중 API의 보호된 API에서 401 받으면 인증 상태 초기화
    useEffect(() => {
        if(status !== 'authenticated') return; // 로그인된 동안에만 감시 시작

        let active = true;

        const interceptorId = apiClient.interceptors.response.use(
            response => response, // 성공 응답일 때는 수정 없이 그대로 전달

            error => {
                // 실패 응답 또는 요청 오류일 때
                const httpStatus = error.response?.status;
                const requestUrl = error.config?.url;
                
                const isLoginRequest = 
                    requestUrl === '/api/v1/auth/login';

                    // 이 인터셉터가 유효하고, 응답이 401이고, 로그인 요청이 아니라면
                    if(active && httpStatus === 401 && !isLoginRequest){
                        // 동시에 여러 요청이 실패해도 한 번만 처리
                        active = false;

                        // 사용자 정보를 지우고 비로그인 상태로 변경
                        setUser(null);
                        setStatus('anonymous');
                        setErrorMessage('로그인 상태가 만료되었거나 해제되었습니다. 다시 로그인 해주세요.');
                    }

                return Promise.reject(error); // 공통 인증 처리를 마친 뒤 원래 API 호출에도 실패 전달
            }
        );

        // 정리 함수 
        return () => {
            active = false; // 이미 진행 중이던 요청에서 늦게 도착한 응답의 상태 변경을 막음
            apiClient.interceptors.response.eject(interceptorId); // 이후 요청에 이 인터셉트가 적용되지 않도록 제거
        };
    },[status]);


    // 로그인 실패 예외는 로그인 화면에서 처리
    async function login(credentials){
        const currentUser = await loginAdmin(credentials);

        setErrorMessage('');

        if(currentUser.role !== 'ROLE_ADMIN'){
            setUser(null);
            setStatus('forbidden');
            return;
        }

        setUser(currentUser);
        setStatus('authenticated');
    }

    // 서버에서 로그아웃에 성공한 뒤 화면 상태도 초기화
    async function logout(){
        await logoutAdmin();

        setUser(null);
        setStatus('anonymous');
        setErrorMessage('');
    }

    // 로그인 상태 조회가 실패했을 때 재시도
    function retrySessionCheck(){
        setCheckVersion(version => version +1);
    }

    return {
        user,
        status,
        errorMessage,
        login,
        logout,
        retrySessionCheck,
    };
}

export default useAuth;

/*

 useAuth.js : 
        서버의 인증 결과를 바탕으로 로그인 상태를 관리하고, 화면에서 사용할 로그인/로그아웃 기능을
        제공하는 커스텀 Hook


 동작 흐름:
 
    > 로그인 시도(첫 번째 useEffect):

            상태를 loading으로 변경
            → GET /api/v1/auth/me 요청
                ├─ 관리자 정보 반환 → user 저장, authenticated
                ├─ 관리자 역할이 아님 → forbidden
                ├─ 401 → anonymous
                ├─ 403 → forbidden
                └─ 통신·서버 오류 → error + 안내 메시지

    > 로그인한 상태로 사용 중일 때(두 번째 useEffect):

            API 요청
            → 401 응답인가?
            → 로그인 요청 자체의 실패는 아닌가?
                → user 제거
                → anonymous로 변경
                → 다시 로그인하라는 안내 설정

    > 로그인 버튼을 눌렀을 때
        LoginPage에서 login(credentials) 호출
        → loginAdmin()으로 로그인 API 요청
            ├─ 관리자 → user 저장, authenticated
            ├─ 다른 역할 → forbidden
            └─ 요청 실패 → LoginPage의 catch로 예외 전달

    > 로그아웃 버튼을 눌렀을 때
        logout() 호출
        → logoutAdmin()으로 서버 세션 무효화 요청
        → 성공하면 user 제거, anonymous로 변경, 안내 초기화

    > 재시도 버튼을 눌렀을 때
        retrySessionCheck()
        → checkVersion 증가
        → 첫 번째 useEffect 재실행
        → /me로 로그인 상태 다시 확인

    > 마지막 return은 상태와 함수를 App이 사용할 수 있도록 내보내는 부분

*/