# 1. FastAPI 테스트 클라이언트 생성
from fastapi.testclient import TestClient
import main

# 2. FakeModel
class FakeModel:
    def predict_proba(self,feautres):
        return [[0.05,0.95]]    # [정상확률, 공격확률]

# 3. FakeEncoder
# 실제 ai 모델에서는 method,user_agent 같은 문자열을 숫자로 바꿔야함
# 이를 위한 것이 LabelEncoder
# 테스트 코드에서는 가짜모델로 검증
class FakeEncoder:
    def __init__(self,classes):
        self.classes_ = classes

    def transfrom(self,values):
        result = []
        for value in values:
            if value in self.classes_:
                result.append(self.classes_.index(value))
            else:
                result.append(self.classes_.index("UNKNOWN"))
        return result

# 4. main.py 안에 있는 실제 전역 변수들을 테스트 중에만 가짜 객체로 바꿔치기
def setup_fake_model(monkeypatch):
    monkeypatch.setattr(main,"model",FakeModel())
    monkeypatch.setattr(main,"le_method",FakeEncoder(["GET","POST","UNKNOWN"]))
    monkeypatch.setattr(main,"le_ua",FakeEncoder(["Mozilla/5.0", "UNKNOWN"]))
    monkeypatch.setattr(main,"le_path",FakeEncoder(["/rest/products/search", "/admin", "UNKNOWN"]))

# 5.
# /prdict에 공격성 요청을 보냈을 때
# FastAPI가 200 응답을 주고
# threat_socre,ip_address,reason을 제대로 반환하는지 확인
def test_predict_attack_request(monkeypatch):
    setup_fake_model(monkeypatch)
    client = TestClient(main.app)

    payload = {
        "method": "GET",
        "url_path": "/rest/products/search",
        "query_params": "q=' OR 1=1--",
        "body_content": "",
        "user_agent": "Mozilla/5.0",
        "url_len": 0,
        "special_char_count": 0,
        "ip_address": "127.0.0.1",
        "timestamp": "2026-05-07T16:00:00"
    }

    # 실제 http 서버를 띄운 게 아닌, TestClient가 내부적으로 FastAPI앱에 요청을 보냄
    response = client.post("/predict",json=payload) 

    assert response.status_code == 200

    data = response.json()
    assert data["threat_score"] == 0.95
    assert data["ip_address"] == "127.0.0.1"
    assert data["reason"] != "-"
    
# 6. 모델이 로드되지 않은 상황을 강제로 만듬
# AI 모델이 없을 때 서버가 이상하게 죽지 않고, 정상적으로 503에러를 반환하는지 확인
def test_predict_when_model_not_loaded(monkeypatch):
    monkeypatch.setattr(main,"model",None)
    client = TestClient(main.app)

    payload = {
        "method": "GET",
        "url_path": "/admin",
        "query_params": "",
        "body_content": "",
        "user_agent": "Mozilla/5.0",
        "url_len": 0,
        "special_char_count": 0,
        "ip_address": "127.0.0.1",
        "timestamp": "2026-05-07T16:00:00"
    }

    response  = client.post("/predict",json= payload)

    assert response.status_code == 503

    