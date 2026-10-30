// WAF 상세 조회 Hook
// API 호출·로딩·오류·이전 요청 취소를 담당

import { useEffect,useState } from "react";
import apiClient from "../api/apiClient";

const EMPTY_STATE = {
    threatId: null,
    detail: null,
    loading: false,
    error: '',
};

function useWafDetail(threatId){
    const [state,setState] = useState(EMPTY_STATE)

    useEffect(()=>{
        if(threatId ==null) return;

        const controller = new AbortController();
        let active = true;

        setState({
            threatId,
            detail: null,
            loading: true,
            error: '',
        });

        async function loadDetail() {
            try{
                const response = await apiClient.get(
                    `/api/v1/threats/${threatId}/waf-detail`,
                    {signal: controller.signal}
                );
                
                if(!active) return;

                setState({
                    threatId,
                    detail: response.data,
                    loading: false,
                    error: '',
                });
            } catch (error){

                if(!active || controller.signal.aborted) return;

                let message = "WAF 상세 정보를 불러오지 못했습니다.";

                if(error.response?.status === 404){
                    message = "해당 위협에 연결된 WAF 상세 정보가 없습니다."
                } else if (error.response?.status === 401){
                    message = "로그인이 만료되었습니다. 다시 로그인해주세요.";
                }

                setState({
                    threatId,
                    detail: null,
                    loading: false,
                    error: message,
                });
            }
        }

        loadDetail();

        return () => {
            // 다른 항목을 열거나 모달을 닫으면 이전 요청을 무효화한다.
            active = false;
            controller.abort();
        };
    }, [threatId]);

    // 새 ID로 바뀐 직후에도 이전 항목을 잠깐 표시하지 않는다.
    if(threatId == null || state.threatId !== threatId){
        return {
            detail: null,
            loading: threatId!=null,
            error: '',
        }
    }

    return state;
}

export default useWafDetail;