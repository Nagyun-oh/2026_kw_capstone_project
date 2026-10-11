/* 인증 상태에 따라 화면 선택 */

import {useRef,useState} from 'react';
import Dashboard from './Dashboard';
import LoginPage from './components/LoginPage';
import useAuth from './hooks/useAuth';

function App() {

  const {
    user,
    status,
    errorMessage,
    login,
    logout,
    retrySessionCheck,
  } = useAuth();

  const [isLoggingOut,setIsLogginOut] = useState(false);
  const [logoutError, setLogoutError] = useState('');
  const loggingOutRef = useRef(false);

  async function handleLogout(){

    if(loggingOutRef.current) return;

    loggingOutRef.current = true;
    setIsLogginOut(true);
    setLogoutError('');

    try{
      await logout();
    }catch (error){
      setLogoutError('로그아웃을 완료하지 못했습니다. 다시 시도해주세요.');
    } finally {
      loggingOutRef.current = false;
      setIsLogginOut(false);
    }
  }

  if(status === 'loading'){
    return (
      <main style = {{padding:'32px'}}>
        <p role="status"> 로그인 상태를 확인하고 있습니다...</p>
      </main>
    );
  }

  if(status === 'anonymous'){
    return (
      <LoginPage
        onLogin={login}
        noticeMessage = {errorMessage}
      />
    );
  }

  if(status === 'error'){
    return (
      <main style ={{padding:'32px'}}>
        <p role="alert">{errorMessage}</p>
        <button type="button" onClick = {retrySessionCheck}>
          다시 시도
        </button>
      </main>
    );
  }

  if(status === 'forbidden'){
    return(
      <main style={{padding: '32px'}}>
        <h1> 접근 권한이 없습니다</h1>
        <p>관리자 계정으로 로그인해주세요.</p>

        <button
          type = "button"
          onClick={handleLogout}
          disabled = {isLoggingOut}
        >
          {isLoggingOut ? '로그아웃 중...' : '로그아웃'}
        </button>

        {logoutError && <p role="alert">{logoutError}</p>}
      </main>
    );
  }

  if (status === 'authenticated'){
    return (
      <Dashboard
        user={user}
        onLogout={handleLogout}
        isLoggingOut={isLoggingOut}
        logoutError={logoutError}
      >
      </Dashboard>
    );
  }

  return (
    <main style= {{padding: '32px'}}>
      <p role= "alert"> 인증 상태를 확인할 수 없습니다.</p>
      <button type= "button" onClick={retrySessionCheck}>
        다시 확인
      </button>
    </main>
  );
}

export default App;

/*
로그아웃 버튼 클릭
  → App.handleLogout()
  → useAuth.logout()
  → authAPI.logoutAdmin()
  → 백엔드에서 세션 무효화
  → user = null, status = anonymous
  → App 다시 렌더링
  → Dashboard 제거·WebSocket 정리
  → LoginPage 표시

*/