-- 선택: 기존 DB에 남아 있는 미사용 Spring Session JDBC 테이블 삭제
-- 백엔드에는 spring-session 의존성이 없고 세션은 서버 메모리에 저장한다(2026/11/08 확인).
-- 새 DB 스키마(security-db-schema.sql)에서는 이미 뺐다. 남아 있어도 동작에는 영향이 없다.
--
-- 적용 전에 대상 DB를 선택하고 두 테이블이 비어 있는지, 다른 서비스가 쓰지 않는지 확인한다.
--   SELECT COUNT(*) FROM SPRING_SESSION;
--   SELECT COUNT(*) FROM SPRING_SESSION_ATTRIBUTES;
-- 자식 테이블(FK)부터 삭제한다. 되돌리려면 이전 security-db-schema.sql의 두 CREATE TABLE을 다시 실행한다.

DROP TABLE IF EXISTS SPRING_SESSION_ATTRIBUTES;
DROP TABLE IF EXISTS SPRING_SESSION;
