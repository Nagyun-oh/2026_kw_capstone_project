-- 전체 로그 목록(created_at 내림차순 페이지 조회)이 테이블 전체를 읽고 정렬하지 않도록
-- created_at 인덱스를 추가한다. 기존 DB에만 적용하며 새 DB는 security-db-schema.sql에 포함돼 있다.
-- 대상 DB를 선택한 상태에서 한 번만 적용한다. 먼저 같은 이름의 인덱스가 없는지 확인한다.
--   SELECT INDEX_NAME FROM information_schema.STATISTICS
--   WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'network_logs'
--     AND INDEX_NAME = 'idx_network_logs_created_at';
-- 온라인 DDL로 추가해 적용 중에도 로그 저장을 막지 않는다. 시작·종료 시 필요한 메타데이터 잠금을
-- 오래 기다리면 실패하도록 대기 시간을 짧게 둔다. 실패하면 장기 트랜잭션을 확인한 뒤 다시 적용한다.
-- 되돌리기: ALTER TABLE network_logs DROP INDEX idx_network_logs_created_at;

SET SESSION lock_wait_timeout = 5;

ALTER TABLE network_logs
    ADD INDEX idx_network_logs_created_at (created_at),
    ALGORITHM = INPLACE,
    LOCK = NONE;
