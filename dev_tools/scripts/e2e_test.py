import subprocess   # subprocess: Python에서 외부 명령어 실행할 때 사용
import time         # Spring이 Kafka 메시지를 처리할 시간을 기다리기 위해 사용
import requests     # Spring API에 HTTP 요청 보내기 위해 사용

KAFKA_CONTAINER = 'kafka'
KAFKA_TOPIC = 'log-topic'
SPRING_BASE_URL = 'http://localhost:8080'

TEST_LOG =  r'{"log":"127.0.0.1 - - [07/May/2026:16:00:00 +0900] \"GET /admin HTTP/1.1\" 403"}'

def send_kafka_message():
    command = [
        "docker","exec","-i",KAFKA_CONTAINER,
        "kafka-console-producer",
        "--topic", KAFKA_TOPIC,
        "--bootstrap-server","localhost:9092"
    ]

    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        text=True
    )

    process.communicate(TEST_LOG +"\n", timeout=10)

    if process.returncode !=0:
        raise RuntimeError("Kafka 메시지 전송 실패")

def check_backend_logs():
    # Spring API에 요청을 보냄
    response = requests.get(f"{SPRING_BASE_URL}/api/v1/logs",timeout=5)
    response.raise_for_status()

    # API 응답 JSON을 Python 리스트/딕셔너리로 변환
    logs = response.json().get("content",[])

    # API/DB 에서 가져온 로그 중에 방금 보낸 테스트 로그와 일치하는 게 있는지 찾음
    matched = [
        log for log in logs
        if log.get("ipAddress") =='127.0.0.1'
        and log.get("requestUrl") == "/admin"
        and log.get("statusCode") == 403
    ]

    # mathced가 비어 있으면 테스트 실패 
    assert matched, "DB/API에서 테스트 로그를 찾지 못했습니다."


if __name__ == "__main__":
    print("[E2E] Kafka 테스트 로그 전송")
    send_kafka_message()

    print("[E2E] Spring 처리 대기")
    time.sleep(3)

    print("[E2E] Backend API에서 로그 저장 확인")
    check_backend_logs()

    print("[E2E] 성공: Kafka -> Spring -> DB -> API 흐름 확인")

'''
진행방식: 
    Kafka에 테스트 로그 전송
    → Spring Consumer가 log-topic에서 수신
    → LogService가 파싱
    → DB 저장
    → Spring API /api/v1/logs로 저장 확인

실행방법:
     → cmd창에서 python .\e2e_test.py 입력 

단점:
    1. Kafka/Spring/DB가 미리 켜저 있어야 함
    2. 이전 테스트 데이터가 DB에 남아 있으면 통과해버릴 수 있음
    3. 실패 원인이 Kafka인지, Spring 인지 , DB인지 세밀하게 구분하기 어려움
    4. CI 자동화에는 아직 조금 부족함
개선 방향:
    나중에는 Docker Compose 기반 E2E로 테스트 방식으로 변경할 것
'''
