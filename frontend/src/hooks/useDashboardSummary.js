// 요약 데이터 관리 훅 함수
/*
    - 최초 진입 시 자동 조회
    - 연속 새로고침 시 이전 요청 취소
    - 로그아웃으로 화면이 사라지면 요청 취소
    - 조회 실패를 0건으로 표시하지 않음
    - 갱신 실패 시 이전 성공 값과 조회 시각 유지
*/

import {useCallback, useEffect, useRef, useState} from 'react';
import { getDashboardSummary } from '../api/dashboardAPI';

function useDashboardSummary(){ 
    const [summary,setSummary] = useState(null);
    const [isLoading, setIsLoading] = useState(true);
    const [errorMessage, setErrorMessage] = useState('');
    const [updatedAt,setUpdatedAt] = useState(null);

    const controllerRef = useRef(null);

    const refreshSummary = useCallback(async () =>{
        // 이전 조회가 진행 중이라면 취소
        controllerRef.current?.abort();

        const controller = new AbortController();
        controllerRef.current = controller;

        setIsLoading(true);
        setErrorMessage('');

        try{
            const data = await getDashboardSummary(controller.signal);

            if(controller.signal.aborted) return;

            setSummary(data);
            setUpdatedAt(new Date());
        } catch (error) {
            if (controller.signal.aborted) return;

            setErrorMessage(
                '요약 정보를 갱신하지 못했습니다. 다시 시도해주세요.'
            );
        } finally {
            if(!controller.signal.aborted){
                setIsLoading(false);
            }
        }
    },[]);

    useEffect(() =>{
        refreshSummary();

        return () =>{
            controllerRef.current?.abort();
        };
    } , [refreshSummary]);

    return {
        summary,
        isLoading,
        errorMessage,
        updatedAt,
        refreshSummary,
    };
}

export default useDashboardSummary;