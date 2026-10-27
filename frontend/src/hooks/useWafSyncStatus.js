import {
  useCallback,
  useEffect,
  useRef,
  useState,
} from 'react';

import { getWafSyncStatus } from '../api/wafSyncAPI';

const POLL_INTERVAL_MS = 10_000;

function useWafSyncStatus() {
  const [data, setData] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState('');

  const controllerRef = useRef(null);

  const refreshWafStatus = useCallback(async () => {
    // 수동 새로고침 등으로 새 요청이 시작되면 이전 요청 취소
    controllerRef.current?.abort();

    const controller = new AbortController();
    controllerRef.current = controller;

    setIsLoading(true);
    setErrorMessage('');

    try {
      const result = await getWafSyncStatus(controller.signal);

      if (controller.signal.aborted) {
        return;
      }

      setData(result);
    } catch (error) {
      if (controller.signal.aborted) {
        return;
      }

      const status = error.response?.status;

      if (status === 401) {
        setData(null);
        setErrorMessage(
          '로그인이 만료되었습니다. 다시 로그인해주세요.'
        );
      } else if (status === 403) {
        setData(null);
        setErrorMessage(
          'WAF 상태를 조회할 관리자 권한이 없습니다.'
        );
      } else {
        // 일반 조회 실패 시 마지막 데이터는 참고용으로 유지
        setErrorMessage(
          'WAF 상태를 조회하지 못했습니다. 현재 적용 상태를 확인할 수 없습니다.'
        );
      }
    } finally {
      if (
        !controller.signal.aborted &&
        controllerRef.current === controller
      ) {
        controllerRef.current = null;
        setIsLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    refreshWafStatus();

    const refreshIfIdle = () => {
      // 자동 조회가 진행 중인 요청을 반복 취소하지 않도록 한다.
      if (controllerRef.current) {
        return;
      }

      refreshWafStatus();
    };

    const intervalId = window.setInterval(
      refreshIfIdle,
      POLL_INTERVAL_MS
    );

    // 다른 탭에서 돌아오면 상태를 다시 확인한다.
    window.addEventListener('focus', refreshIfIdle);

    return () => {
      window.clearInterval(intervalId);
      window.removeEventListener('focus', refreshIfIdle);
      controllerRef.current?.abort();
    };
  }, [refreshWafStatus]);

  return {
    data,
    isLoading,
    errorMessage,
    refreshWafStatus,
  };
}

export default useWafSyncStatus;

/*
조회·자동 갱신 Hook
이 Hook의 역할:
- 대시보드 진입 시 최초 조회.
- 10초 간격 자동 조회.
- 조회 중이면 자동 요청 중복 방지.
- 수동 새로고침 시 이전 요청 취소.
- 로그아웃으로 대시보드가 사라지면 타이머·요청 정리.
- 조회 실패 시 이전 성공 상태를 현재 상태로 표시하지 않음.
*/