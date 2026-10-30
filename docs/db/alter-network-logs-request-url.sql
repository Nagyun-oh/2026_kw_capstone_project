-- 긴 요청 URL 저장을 위해 VARCHAR(255)를 TEXT로 확장한다.
-- 대상 DB를 선택한 상태에서 적용한다.
-- 기존 데이터와 NULL 허용 여부를 유지한다.

ALTER TABLE network_logs
    MODIFY COLUMN request_url TEXT NULL;