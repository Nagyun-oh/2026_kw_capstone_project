import { useEffect,useRef } from "react";

// 전체 자동 갱신 훅
function useDashboardAutoRefresh(
    refresh,
    intervalMs = 10_000
){
    const refreshRef = useRef(refresh);

    // 타이머에서는 최신 검색 조건을 가진 함수를 사용한다.
    useEffect(()=> {
        refreshRef.current = refresh;
    },[refresh]);

    useEffect(()=>{
        let stopped = false;
        let running = false;
        let timerId = null;

        async function run(){
            if(stopped || document.hidden || running){
                return;
            }

            running = true;

            try{
                await refreshRef.current();
            } catch(error){
                console.error('대시보드 자동 갱신 처리 실패',error);
            } finally{
                running = false;

                // 조회 완료 후 다음 주기를 예약한다.
                if(!stopped && !document.hidden){
                    timerId = window.setTimeout(run,intervalMs);
                }
            }
        }

        function handleVisibilityChange(){
            window.clearTimeout(timerId);

            if(!document.hidden){
                void run();
            }
        }

        void run();

        document.addEventListener(
            'visibilitychange',
            handleVisibilityChange
        );

        return() => {
            stopped = true;
            window.clearTimeout(timerId);

            document.removeEventListener(
                'visibilitychange',
                handleVisibilityChange
            );
        };
    },[intervalMs]);
}

export default useDashboardAutoRefresh;