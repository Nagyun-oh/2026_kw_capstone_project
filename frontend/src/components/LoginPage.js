
/* 아이디·비밀번호 입력, 제출, 로그인 오류 표시 */

import {useRef,useState} from 'react';
import '../styles/login.css';

function LoginPage({onLogin,noticeMessage = ''}){

    // 입력값과 화면 상태 저장
    const [username,setUsername] = useState('');                // 입력한 아이디
    const [password,setPassword] = useState('');                // 입력한 비밀번호
    const [isSubmitting,setIsSubmitting] = useState(false);     // 로그인 요청 진행 중인지
    const [errorMessage, setErrorMessage] = useState('');       // 로그인 실패 메시지

    // 연속 클릭·Enter 입력으로 요청이 중복되는 것을 방지
    const submittingRef = useRef(false);

    async function handleSubmit(event){
        event.preventDefault();

        if(submittingRef.current) return;

        submittingRef.current = true;
        setIsSubmitting(true);
        setErrorMessage('');

        try{
            // 로그인 시도
            await onLogin({
                username: username.trim(),
                password,
            });
        } catch (error){
            // 실패했을 때 처리
            const httpStatus = error.response?.status;

            if(httpStatus === 401){
                setErrorMessage("아이디 또는 비밀번호를 확인해주세요.");
            } else if(httpStatus === 403){
                setErrorMessage("요청이 거부되었습니다. 페이지를 새로고침한 뒤 다시 시도해주세요.");
            } else if(httpStatus ===400){
                setErrorMessage("아이디와 비밀번호를 확인해주세요.")
            } else {
                setErrorMessage("서버에 연결하지 못했거나 오류가 발생했습니다. 잠시 후 다시 시도해주세요.");
            }
            setPassword('');
        } finally {
        // 성공·실패 모두 실행: 제출 중 상태 해제
        submittingRef.current = false;
        setIsSubmitting(false);
        } 
    }

    return (
        <main className='login-page'>
            <div className='login-shell'>
                <aside className='login-brand'>
                    <div className='login-brand__identity'>
                        <span
                            className='login-brand__mark'
                            aria-hidden="true"
                        >
                            s
                        </span>
                        <span>Security Monitor</span>
                    </div>

                    <div className='login-brand__intro'>
                        <p className='login-eyebrow'>
                            SECURITY_MONITORING
                        </p>

                        <h2>
                            보안 위협을<br />
                            한눈에 확인하세요.
                        </h2>

                        <p className='login-brand__description'>
                            수집된 요청부터 위협 탐지 결과까지,
                            관리자 대시보드에서 확인하세요.
                        </p>
                    </div>

                    <p className='login-brand__footer'>
                        AI 기반 보안 위협 분석 시스템
                    </p>
                </aside>

                <section
                    className='login-panel'
                    aria-labelledby='login-title'
                >
                    <header className='login-heading'>
                        <p className='login-eyebrow'>
                            ADMIN ACCESS
                        </p>

                        <h1 id='login-title'>관리자 로그인</h1>

                        <p>
                            발급받은 관리자 계정으로 로그인하세요.
                        </p>
                    </header>

                    {noticeMessage && (
                        <p
                            className='login-message login-message--notice'
                            role='status'
                        >
                            {noticeMessage}
                        </p>
                    )}

                    <form
                        className='login-form'
                        onSubmit={handleSubmit}
                        aria-busy={isSubmitting}
                    >
                        <fieldset disabled={isSubmitting}>
                            <legend className='login-sr-only'>
                                로그인 정보
                            </legend>
                            
                            <div className='login-field'>
                                <label htmlFor='username'>
                                    아이디
                                </label>

                                <input
                                    id='username'
                                    name='username'
                                    type='text'
                                    autoComplete='username'
                                    autoCapitalize='none'
                                    spellCheck={false}
                                    placeholder='관리자 아이디'
                                    required
                                    maxLength={50}
                                    value={username}
                                    onChange={event =>
                                        setUsername(event.target.value)
                                    }
                                
                                />
                            </div>

                            <div className="login-field">
                                <label htmlFor="password">
                                    비밀번호
                                </label>

                                <input
                                    id="password"
                                    name="password"
                                    type="password"
                                    autoComplete="current-password"
                                    placeholder="비밀번호 입력"
                                    required
                                    value={password}
                                    onChange={event =>
                                        setPassword(event.target.value)
                                    }
                                />
                            </div>            

                            <button
                                type='submit'
                                className='login-submit'
                            >
                                {isSubmitting
                                    ? '로그인 중…'
                                    : '로그인'
                                }
                            </button>
                        </fieldset>       
    
                        {errorMessage && (
                            <p
                                className='login-message login-message--error'
                                role='alert'
                            >
                                {errorMessage}
                            </p>
                        )}            
                    </form>
                        
                    <p className='login-account-help'>
                        계정이 필요한 경우 시스템 운영자에게 문의하세요.
                    </p>

                </section>
            </div>
        </main>
    );
}

export default LoginPage;








