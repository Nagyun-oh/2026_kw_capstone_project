"""샘플 요청을 로컬 WAF로 전송하고, WAF 탐지 / AI 판정 / 파이프라인 저장 결과를 비교한다.

전제: 루트 compose.yaml 스택이 로컬에서 실행 중이어야 한다. (WAF 80, AI 8000, MySQL 컨테이너 security-mysql)
입력: dev_tools/datasets/sample.jsonl (sample_test_requests.py가 생성)
출력: dev_tools/datasets/results.csv, dev_tools/datasets/report.md (둘 다 Git 제외 대상)

판정 수집 방법
- WAF   : --waf-mode로 고른다. 두 방식 모두 요청 단계 탐지만 센다(AI도 요청만 보므로).
          audit(기본): 요청마다 X-Sample-Id 헤더를 붙이고, waf-audit.log에서 같은 ID의 매칭 룰을 읽는다.
                       949110(요청 이상 점수 5 이상) 또는 커스텀 룰 10001~10003이면 탐지다.
                       응답 단계 점수(959100)는 waf_outbound_score로 기록만 한다. (DetectionOnly라 차단되지 않는다.)
          status     : 차단 모드 WAF의 응답 코드(--block-status, 기본 403)로 판정한다. 로그 형식이 다른
                       WAF끼리 비교할 때 쓴다(wafs/ 실험실, 응답 단계 차단을 끈 설정). --baseline-port로 WAF 없이
                       같은 앱에 보낸 응답도 받아, 앱 자체가 차단 코드를 준 요청은 WAF 탐지로 세지 않는다.
                       메인 파이프라인을 거치지 않으므로 DB 확인은 건너뛴다.
- AI    : 백엔드가 AI에 보내는 것과 같은 필드로 /predict/batch를 직접 호출한다.
          (백엔드의 자동 블랙리스트 같은 부수효과 없이 모델 판정만 본다.)
          전송 전에 /health로 모델 로드를 확인하고, 묶음 호출이 실패하면 재시도한다.
          재시도 후에도 실패한 요청은 비교에서 빼고 리포트에 건수를 남긴다.
          --ai-url에 쉼표로 여러 서버를 주면 나눠 보낸다(AI 서버는 요청을 하나씩 처리한다).
          --ai-cache 파일에 판정을 저장해 두면 같은 요청은 다시 묻지 않는다. AI 판정은 WAF와 무관하게
          같으므로 WAF·설정을 바꿔 여러 번 실행할 때 쓴다. 모델 정보(/health)가 다르면 캐시를 쓰지 않는다.
- 저장  : 같은 요청이 Kafka -> 백엔드 -> AI -> MySQL을 거쳐 detected_threats에 저장됐는지 확인한다.
          (AI 직접 호출 결과와 파이프라인 결과가 일치하는지 검증하는 용도)

리포트의 비율 옆 범위는 95% 신뢰구간(Wilson score)이다. 표본이 작은 유형·출처일수록 범위가 넓다.
입력 샘플 옆에 sample_test_requests.py가 만든 .meta.json(원본 층별 건수)이 있으면, 층마다 뽑은 비율이
달라 생기는 치우침을 없애려고 전체 탐지율·오탐률을 원본 구성으로 가중 평균한 값과, 실제 공격 비율을
가정한 정밀도(--base-rates)를 함께 낸다. 라벨이 의심되는 정상 출처(--suspect-benign-sources)를 뺀
오탐률도 낸다.

사용 예:
    python3 dev_tools/scripts/run_pipeline_test.py --limit 50      # 먼저 소량으로 확인
    python3 dev_tools/scripts/run_pipeline_test.py                 # 전체 실행
    python3 dev_tools/scripts/run_pipeline_test.py --skip-db --out-dir dev_tools/datasets/run-t1-pl4
    python3 dev_tools/scripts/run_pipeline_test.py --waf-mode status --waf-port 8091 \\
        --label coraza-crs --out-dir dev_tools/datasets/lab-coraza       # wafs/docker-compose.yml 실험실
    python3 dev_tools/scripts/run_pipeline_test.py --input dev_tools/datasets/sample-census.jsonl \\
        --waf-mode status --waf-port 8091 --label coraza-crs \\
        --ai-url http://127.0.0.1:8101,http://127.0.0.1:8102 --ai-cache dev_tools/datasets/ai-cache-census.jsonl \\
        --out-dir dev_tools/datasets/census-coraza
"""
import argparse
import csv
import hashlib
import http.client
import json
import math
import queue
import subprocess
import threading
import time
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlsplit

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = PROJECT_ROOT / "dev_tools" / "datasets"
AUDIT_LOG = PROJECT_ROOT / "waf" / "logs" / "waf-audit.log"

# 개별 탐지가 아니라 누적 점수 판정 룰. 요청 단계만 탐지로 센다.
INBOUND_SCORE_RULE = "949110"
OUTBOUND_SCORE_RULE = "959100"
INBOUND_THRESHOLD = 5   # compose의 ANOMALY_INBOUND와 같은 값
DROP_HEADERS = {"host", "content-length", "connection", "accept-encoding", "transfer-encoding",
                "x-sample-id", "keep-alive", "proxy-connection", "upgrade", "te"}
AI_BATCH_SIZE = 100
AI_RETRIES = 3
AI_RESULT_FIELDS = ("threat_score", "ip_address", "reason")


def load_samples(path: Path, limit: int) -> list:
    if not path.exists():
        raise SystemExit(f"입력 파일이 없습니다: {path}\n먼저 sample_test_requests.py로 샘플을 만드세요.")
    with open(path, encoding="utf-8") as f:
        samples = [json.loads(line) for line in f if line.strip()]
    if limit:
        samples = samples[:limit]
    if not samples:
        raise SystemExit(f"입력 파일에 요청이 없습니다: {path}")
    return samples


def encode_uri(path: str, query: str) -> str:
    """공백·제어문자·비ASCII만 퍼센트 인코딩한다. 이미 있는 %XX와 공격 문자열(' < > 등)은 그대로 둔다."""
    safe = "/%:@!$&'()*+,;=-._~?#[]<>\"{}|\\^`"
    uri = path or "/"
    if query:
        uri += "?" + query
    if not uri.startswith("/"):
        uri = "/" + uri
    return quote(uri, safe=safe)


def build_request(sample: dict, run_id: str) -> dict:
    uri = encode_uri(sample["path"], sample.get("query") or "")
    headers, user_agent = {}, ""
    for name, value in sample.get("headers") or []:
        lowered = name.lower()
        if lowered == "user-agent":
            user_agent = value
        if lowered in DROP_HEADERS:
            continue
        headers[name] = value
    headers["X-Sample-Id"] = f"SID-{run_id}-{sample['sample_id']}"
    body = (sample.get("body") or "").encode("utf-8")
    if body and sample.get("content_type") and not any(k.lower() == "content-type" for k in headers):
        headers["Content-Type"] = sample["content_type"]
    split = urlsplit(uri)
    return {
        "method": sample["method"], "uri": uri, "headers": headers, "body": body,
        "user_agent": user_agent, "url_path": split.path, "query": split.query,
    }


_connections = threading.local()
SEND_RETRIES = 2


def send(req: dict, host: str, port: int) -> str:
    """요청 하나를 보내고 응답 코드를 돌려준다. 연결은 스레드마다 재사용한다(keep-alive).

    요청마다 새 연결을 열면 수만 건 규모에서 닫힌 연결(TIME_WAIT)이 포트를 다 써 Docker 포트 중계가
    연결을 끊는다(ConnectionResetError가 구간 단위로 몰림). 끊긴 연결은 새로 열어 다시 보낸다.
    """
    pool = getattr(_connections, "pool", None)
    if pool is None:
        pool = _connections.pool = {}
    last_error = None
    for attempt in range(SEND_RETRIES + 1):
        conn = pool.get((host, port))
        if conn is None:
            conn = pool[(host, port)] = http.client.HTTPConnection(host, port, timeout=20)
        try:
            conn.request(req["method"], req["uri"], body=req["body"] or None, headers=req["headers"])
            response = conn.getresponse()
            response.read()
            if response.will_close:
                conn.close()
                pool.pop((host, port), None)
            return str(response.status)
        except Exception as exc:  # 전송 실패도 결과로 남긴다.
            conn.close()
            pool.pop((host, port), None)
            last_error = exc
            time.sleep(0.2 * (attempt + 1))
    return f"ERR:{type(last_error).__name__}"


def send_all(requests_: list, host: str, port: int, workers: int, label: str) -> list:
    """요청을 병렬로 보내고 응답 코드를 순서대로 돌려준다. 많을 때는 10%마다 진행 상황을 출력한다."""
    statuses = []
    step = max(len(requests_) // 10, 1000)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for start in range(0, len(requests_), step):
            statuses.extend(pool.map(lambda r: send(r, host, port), requests_[start:start + step]))
            if len(requests_) > step:
                print(f"  {label}: {len(statuses)}/{len(requests_)}", flush=True)
    return statuses


def check_ai_ready(ai_urls: list) -> dict:
    """전송 전에 AI 모델 상태를 확인하고, 캐시 구분에 쓸 모델 정보를 돌려준다.

    전송 뒤에 AI가 없음을 알면 실행 전체를 다시 해야 한다. 여러 서버는 같은 모델이어야 한다.
    """
    fingerprints = []
    for url in ai_urls:
        try:
            with urllib.request.urlopen(f"{url}/health", timeout=10) as resp:
                health = json.loads(resp.read())
        except (OSError, ValueError) as exc:
            raise SystemExit(f"AI 서버에 연결할 수 없습니다({url}/health): {exc}")
        if health.get("model_loaded") is not True:
            raise SystemExit(f"AI 모델이 아직 로드되지 않았습니다({url}): {health}")
        fingerprints.append({key: value for key, value in health.items() if key != "status"})
    if any(fp != fingerprints[0] for fp in fingerprints):
        raise SystemExit(f"AI 서버들의 모델 정보가 다릅니다: {fingerprints}")
    return fingerprints[0]


def ai_input(req: dict) -> dict:
    return {
        "method": req["method"], "url_path": req["url_path"], "query_params": req["query"],
        "body_content": req["body"].decode("utf-8", "replace"), "user_agent": req["user_agent"],
        "ip_address": "10.0.0.1",
    }


def ai_key(item: dict) -> str:
    return hashlib.sha256(json.dumps(item, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def load_ai_cache(path, fingerprint: dict) -> dict:
    """캐시 파일: 첫 줄은 모델 정보, 이후 한 줄에 판정 하나. 모델 정보가 다르면 쓰지 않고 멈춘다."""
    if path is None or not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        header = json.loads(f.readline() or "{}")
        if header.get("fingerprint") != fingerprint:
            raise SystemExit(f"AI 캐시의 모델 정보가 현재 AI와 다릅니다. 다른 --ai-cache 파일을 지정하세요: {path}\n"
                             f"  캐시: {header.get('fingerprint')}\n  현재: {fingerprint}")
        cache = {}
        for line in f:
            try:
                entry = json.loads(line)
                cache[entry["key"]] = entry["result"]
            except (json.JSONDecodeError, KeyError):
                continue   # 실행이 중간에 끊겨 마지막 줄이 잘렸을 수 있다.
        return cache


def call_ai(requests_: list, ai_urls: list, cache_path=None, fingerprint=None) -> dict:
    """요청 순번(1부터) -> AI 판정. 재시도 후에도 실패한 묶음의 요청은 결과에 없다.

    AI 서버마다 작업 스레드를 하나 두고 100건 묶음을 나눠 처리한다. 판정은 묶음마다 캐시에 바로 쓴다.
    """
    items = [ai_input(r) for r in requests_]
    keys = [ai_key(item) for item in items]
    cached = load_ai_cache(cache_path, fingerprint)
    results = {n: cached[key] for n, key in enumerate(keys, start=1) if key in cached}
    todo = [n for n in range(1, len(items) + 1) if n not in results]
    if cache_path is not None:
        print(f"AI 캐시: {len(results)}건 재사용, {len(todo)}건 새로 판정", flush=True)

    chunks = queue.Queue()
    for start in range(0, len(todo), AI_BATCH_SIZE):
        chunks.put(todo[start:start + AI_BATCH_SIZE])
    lock = threading.Lock()
    progress = {"done": 0, "next_report": max(len(todo) // 20, AI_BATCH_SIZE)}
    started = time.monotonic()
    cache_file = None
    if cache_path is not None and todo:
        is_new = not cache_path.exists()
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_file = open(cache_path, "a", encoding="utf-8")
        if is_new:
            cache_file.write(json.dumps({"fingerprint": fingerprint, "created": datetime.now().isoformat()},
                                        ensure_ascii=False) + "\n")

    def worker(url: str) -> None:
        while True:
            try:
                chunk = chunks.get_nowait()
            except queue.Empty:
                return
            payload = [dict(items[n - 1], log_id=n) for n in chunk]
            http_req = urllib.request.Request(f"{url}/predict/batch", json.dumps(payload).encode(),
                                              {"Content-Type": "application/json"})
            got = {}
            for attempt in range(1, AI_RETRIES + 1):
                try:
                    with urllib.request.urlopen(http_req, timeout=120) as resp:
                        # 순서가 아니라 log_id로 맞춘다. 응답 개수가 모자라도 다른 요청과 섞이지 않는다.
                        got = {item["log_id"]: {f: item[f] for f in AI_RESULT_FIELDS}
                               for item in json.loads(resp.read())["results"]}
                    break
                except (OSError, ValueError, KeyError, TypeError) as exc:  # URLError·HTTPError·timeout은 OSError
                    if attempt == AI_RETRIES:
                        print(f"[warn] AI 호출 실패, 비교에서 제외: {chunk[0]}~{chunk[-1]}번 "
                              f"({type(exc).__name__}: {exc})", flush=True)
                    else:
                        time.sleep(2 * attempt)
            with lock:
                for n, result in got.items():
                    if n in chunk:
                        results[n] = result
                        if cache_file is not None:
                            cache_file.write(json.dumps({"key": keys[n - 1], "result": result},
                                                        ensure_ascii=False) + "\n")
                if cache_file is not None:
                    cache_file.flush()
                progress["done"] += len(chunk)
                if progress["done"] >= progress["next_report"] or progress["done"] == len(todo):
                    elapsed = time.monotonic() - started
                    rate = progress["done"] / elapsed if elapsed else 0
                    eta = (len(todo) - progress["done"]) / rate if rate else 0
                    print(f"  AI 판정: {progress['done']}/{len(todo)} ({rate:.0f}건/s, 남은 시간 약 {eta / 60:.0f}분)",
                          flush=True)
                    progress["next_report"] += max(len(todo) // 20, AI_BATCH_SIZE)

    threads = [threading.Thread(target=worker, args=(url,)) for url in ai_urls]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if cache_file is not None:
        cache_file.close()
    return results


def read_waf_audit(run_id: str) -> dict:
    """waf-audit.log에서 이번 실행의 요청별 매칭 룰을 모은다."""
    found = {}
    if not AUDIT_LOG.exists():
        return found
    with open(AUDIT_LOG, encoding="utf-8", errors="replace") as f:
        for line in f:
            if run_id not in line:
                continue
            try:
                tx = json.loads(line)["transaction"]
            except (json.JSONDecodeError, KeyError):
                continue
            headers = {k.lower(): v for k, v in (tx.get("request", {}).get("headers") or {}).items()}
            sid = headers.get("x-sample-id", "")
            if not sid.startswith(f"SID-{run_id}-"):
                continue
            rules, scores = [], {}
            for message in tx.get("messages", []):
                rule_id = str((message.get("details") or {}).get("ruleId", ""))
                if rule_id in (INBOUND_SCORE_RULE, OUTBOUND_SCORE_RULE):
                    text = message.get("message") or ""
                    if "Total Score:" in text:
                        scores[rule_id] = int(text.split("Total Score:")[1].split(")")[0].strip().split()[0])
                elif rule_id:
                    rules.append(rule_id)
            inbound = scores.get(INBOUND_SCORE_RULE)
            custom = any(r.isdigit() and int(r) < 100000 and r.startswith("1000") for r in rules)
            # 응답 단계 점수는 요청 탐지가 아니므로(AI는 요청만 본다) 판정에 넣지 않고 기록만 한다.
            found[sid.split("-", 2)[2]] = {"rules": rules, "score": inbound,
                                           "outbound_score": scores.get(OUTBOUND_SCORE_RULE),
                                           "block": custom or (inbound is not None and inbound >= INBOUND_THRESHOLD)}
    return found


def status_verdicts(samples: list, statuses: list, baselines: list, block_status: set) -> dict:
    """차단 모드 WAF의 응답 코드로 요청별 판정을 만든다.

    기준선(WAF 없이 보낸 응답)도 차단 코드면 앱 자체 응답이라 WAF 차단과 구분할 수 없다.
    이런 요청은 판정 불가로 표시하고 탐지하지 않은 것으로 센다(WAF 탐지율을 부풀리지 않도록).
    """
    found = {}
    for sample, status, baseline in zip(samples, statuses, baselines):
        blocked = status in block_status
        ambiguous = blocked and baseline in block_status
        found[sample["sample_id"]] = {"rules": [], "score": None, "block": blocked and not ambiguous,
                                      "ambiguous": ambiguous}
    return found


def read_pipeline_db(run_id: str, container: str) -> dict:
    """network_logs/detected_threats에서 이번 실행의 요청별 저장·위협 건수를 읽는다."""
    sql = ("SELECT REGEXP_SUBSTR(l.raw_log,'SID-%s-s[0-9]+') sid, COUNT(t.id) "
           "FROM network_logs l LEFT JOIN detected_threats t ON t.log_id=l.id "
           "WHERE l.raw_log LIKE '%%SID-%s-%%' GROUP BY l.id, sid" % (run_id, run_id))
    cmd = ["docker", "exec", container, "sh", "-c",
           'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot -D security_db -N -B -e "$0"', sql]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    result = {}
    for line in out.stdout.splitlines():
        sid, _, count = line.partition("\t")
        if sid:
            result[sid.split("-", 2)[2]] = int(count or 0)
    return result


def wait_until_stable(read_fn, expected: int, timeout: int, label: str):
    """결과 건수가 더 늘지 않을 때까지(또는 기대 건수에 도달할 때까지) 기다린다."""
    deadline, last, stable_since = time.time() + timeout, -1, time.time()
    while time.time() < deadline:
        data = read_fn()
        if len(data) >= expected:
            return data
        if len(data) != last:
            last, stable_since = len(data), time.time()
        elif time.time() - stable_since > 20:
            break
        time.sleep(3)
    print(f"[warn] {label}: {len(data)}/{expected}건만 수집됨")
    return data


def wilson_interval(n: int, d: int, z: float = 1.96) -> tuple:
    """비율 n/d의 95% 신뢰구간. 정규근사와 달리 0%·100% 근처나 작은 표본에서도 범위가 0~1을 넘지 않는다."""
    p = n / d
    denominator = 1 + z * z / d
    center = (p + z * z / (2 * d)) / denominator
    half = z * math.sqrt(p * (1 - p) / d + z * z / (4 * d * d)) / denominator
    return max(0.0, center - half), min(1.0, center + half)


def pct(n: int, d: int) -> str:
    if not d:
        return "-"
    low, high = wilson_interval(n, d)
    return f"{n}/{d} ({100 * n / d:.1f}%, {100 * low:.1f}~{100 * high:.1f})"


def load_population(input_path: Path):
    """sample_test_requests.py가 남긴 .meta.json에서 원본 층별 건수를 읽는다. 없으면 None."""
    meta_path = input_path.with_name(input_path.stem + ".meta.json")
    if not meta_path.exists():
        return None
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    return {(label, source, family): count for label, source, family, count, _ in meta["strata"]}


def stratum_key(row: dict) -> tuple:
    return (row["label"], row["source"], row["family"])


def weighted_rate(rows: list, population: dict, predicate, exclude_sources=()):
    """층별 비율을 원본 건수로 가중 평균한다. (비율, 근사 95% 오차) 또는 None.

    샘플은 층마다 뽑은 비율이 달라 단순 합계는 샘플 구성대로 가중된다. 원본 구성으로 되돌려 계산한다.
    오차는 층별 이항 분산의 가중 합으로 구한 정규 근사다.
    """
    groups = defaultdict(list)
    for row in rows:
        if row["source"] not in exclude_sources and stratum_key(row) in population:
            groups[stratum_key(row)].append(row)
    total = sum(population[key] for key in groups)
    if not total:
        return None
    rate = variance = 0.0
    for key, items in groups.items():
        weight = population[key] / total
        p = sum(bool(predicate(r)) for r in items) / len(items)
        rate += weight * p
        variance += weight * weight * p * (1 - p) / len(items)
    return rate, 1.96 * math.sqrt(variance)


def population_coverage(rows: list, population: dict, label: int) -> float:
    """샘플에 들어온 층이 원본에서 차지하는 비중. 1보다 작으면 환산값은 들어온 층만의 값이다."""
    present = {stratum_key(r) for r in rows}
    total = sum(n for key, n in population.items() if key[0] == label)
    return sum(n for key, n in population.items() if key[0] == label and key in present) / total if total else 0


def build_report(rows: list, label: str = "", waf_note: str = "", population=None,
                 suspect_sources=(), base_rates=()) -> str:
    sent = [r for r in rows if not r["send_error"]]
    compared = [r for r in sent if not r["ai_error"]]
    attacks = [r for r in compared if r["label"] == 1]
    benign = [r for r in compared if r["label"] == 0]
    title = "# WAF vs AI 탐지 비교" + (f" ({label})" if label else "")
    lines = [title, "", f"- 전송 성공: {len(sent)}/{len(rows)}건"]
    if waf_note:
        lines.append(f"- WAF 판정: {waf_note}")
    ambiguous = sum(r["waf_ambiguous"] for r in sent)
    if ambiguous:
        lines.append(f"- WAF 판정 불가: {ambiguous}건 (WAF 없이 보낸 응답도 차단 코드여서 미탐지로 집계)")
    server_errors = sum(r["status"].startswith("5") for r in sent)
    if server_errors:
        lines.append(f"- WAF 응답 5xx: {server_errors}건 (백엔드가 멈췄을 수 있다. 측정 중 백엔드 상태 확인)")
    ai_failed = sum(r["ai_error"] for r in sent)
    if ai_failed:
        lines.append(f"- AI 판정 실패: {ai_failed}건 (재시도 후에도 실패, 비교에서 제외)")
    lines += [f"- 비교 대상: 공격 {len(attacks)}, 정상 {len(benign)}",
              "- 표기: 건수 (비율, 95% 신뢰구간 Wilson)", ""]

    def block(title, items):
        w = sum(r["waf_detected"] for r in items)
        a = sum(r["ai_attack"] for r in items)
        both = sum(r["waf_detected"] and r["ai_attack"] for r in items)
        either = sum(r["waf_detected"] or r["ai_attack"] for r in items)
        return [f"| {title} | {len(items)} | {pct(w, len(items))} | {pct(a, len(items))} | "
                f"{pct(both, len(items))} | {pct(either, len(items))} |"]

    header = ["| 구분 | 건수 | WAF | AI | 둘 다 | 하나라도 |", "|---|---|---|---|---|---|"]
    lines += ["## 전체", "", *header, *block("공격(탐지율)", attacks), *block("정상(오탐률)", benign), ""]

    verdicts = (
        ("WAF", lambda r: r["waf_detected"]),
        ("AI", lambda r: r["ai_attack"]),
        ("둘 다(AND)", lambda r: r["waf_detected"] and r["ai_attack"]),
        ("하나라도(OR)", lambda r: r["waf_detected"] or r["ai_attack"]),
    )
    if population is None:
        lines += ["- 원본 구성 정보(.meta.json)가 없어 원본 비율로 환산하지 않았다.", ""]
    else:
        cell = lambda value: "-" if value is None else f"{100 * value[0]:.1f}% ±{100 * value[1]:.1f}"
        tpr = [weighted_rate(attacks, population, fn) for _, fn in verdicts]
        fpr = [weighted_rate(benign, population, fn) for _, fn in verdicts]
        table = [f"| 탐지율 | {' | '.join(cell(v) for v in tpr)} |",
                 f"| 오탐률 | {' | '.join(cell(v) for v in fpr)} |"]
        suspects = [s for s in suspect_sources if any(r["source"] == s for r in benign)]
        if suspects:
            fpr_clean = [weighted_rate(benign, population, fn, exclude_sources=suspects) for _, fn in verdicts]
            table.append(f"| 오탐률({','.join(suspects)} 제외) | {' | '.join(cell(v) for v in fpr_clean)} |")
        for base in base_rates:
            # 정밀도 = 탐지율·공격비율 / (탐지율·공격비율 + 오탐률·정상비율)
            values = []
            for t, f in zip(tpr, fpr):
                if t is None or f is None or t[0] * base + f[0] * (1 - base) == 0:
                    values.append("-")
                else:
                    values.append(f"{100 * t[0] * base / (t[0] * base + f[0] * (1 - base)):.1f}%")
            table.append(f"| 정밀도(공격 {100 * base:g}% 가정) | {' | '.join(values)} |")
        coverage = (population_coverage(attacks, population, 1), population_coverage(benign, population, 0))
        lines += ["## 원본 구성으로 환산", "",
                  "층마다 뽑은 비율이 달라 위 표의 합계는 샘플 구성대로 가중된다. 아래는 층별 비율을 원본"
                  "(길이 제한·중복·라벨 충돌 제외 후) 건수로 가중 평균한 값이다. ±는 정규 근사 95% 범위다.",
                  f"원본 중 샘플에 들어온 층의 비중: 공격 {100 * coverage[0]:.1f}%, 정상 {100 * coverage[1]:.1f}%.",
                  "정밀도는 환산 탐지율·오탐률에 실제 공격 비율을 가정해 계산했다.", "",
                  f"| 구분 | {' | '.join(name for name, _ in verdicts)} |", "|---|---|---|---|---|", *table, ""]

    for key, title in (("family", "공격 유형별"), ("source", "출처별(공격)")):
        groups = defaultdict(list)
        for r in attacks:
            groups[r[key]].append(r)
        lines += [f"## {title}", "", *header]
        for name, items in sorted(groups.items()):
            lines += block(name, items)
        lines.append("")

    groups = defaultdict(list)
    for r in benign:
        groups[r["source"]].append(r)
    lines += ["## 출처별(정상, 오탐)", "", *header]
    for name, items in sorted(groups.items()):
        lines += block(name, items)

    only_waf = sum(r["waf_detected"] and not r["ai_attack"] for r in attacks)
    only_ai = sum(r["ai_attack"] and not r["waf_detected"] for r in attacks)
    neither = sum(not r["waf_detected"] and not r["ai_attack"] for r in attacks)
    lines += ["", "## 공격 요청 분포", "", f"- WAF만 탐지: {only_waf}", f"- AI만 탐지: {only_ai}",
              f"- 둘 다 놓침: {neither}", ""]

    checked = [r for r in sent if r["db_threats"] is not None]
    if checked:
        judged = [r for r in checked if not r["ai_error"]]
        agree = sum((r["db_threats"] > 0) == r["ai_attack"] for r in judged)
        lines += ["## 파이프라인 검증", "",
                  f"- DB에 저장된 로그: {len(checked)}/{len(sent)}건",
                  f"- AI 직접 호출 결과와 DB 위협 저장 일치: {pct(agree, len(judged))}", ""]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DATASET_DIR / "sample.jsonl")
    parser.add_argument("--limit", type=int, default=0, help="앞에서 N건만 실행(0이면 전체)")
    parser.add_argument("--waf-host", default="localhost")
    parser.add_argument("--waf-port", type=int, default=80)
    parser.add_argument("--ai-url", default="http://localhost:8000", help="AI 서버 주소(쉼표로 여러 개)")
    parser.add_argument("--ai-cache", type=Path, default=None, help="AI 판정 캐시 파일(jsonl). 없으면 만든다")
    parser.add_argument("--db-container", default="security-mysql")
    parser.add_argument("--skip-db", action="store_true")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--out-dir", type=Path, default=DATASET_DIR,
                        help="results.csv·report.md 저장 위치. 이전 결과를 남기려면 실행마다 다르게 지정")
    parser.add_argument("--waf-mode", choices=("audit", "status"), default="audit",
                        help="audit: 메인 WAF 감사 로그로 판정, status: 차단 모드 WAF의 응답 코드로 판정")
    parser.add_argument("--block-status", default="403", help="status 모드에서 차단으로 볼 응답 코드(쉼표 구분)")
    parser.add_argument("--baseline-host", default="localhost")
    parser.add_argument("--baseline-port", type=int, default=0,
                        help="status 모드 기준선: WAF 없이 같은 앱에 보낼 포트(0이면 비교하지 않음)")
    parser.add_argument("--label", default="", help="리포트 제목에 붙일 이름(예: coraza-crs)")
    parser.add_argument("--suspect-benign-sources", default="ecml",
                        help="라벨이 의심돼 오탐률을 따로 뺀 값도 낼 정상 출처(쉼표 구분, 빈 값이면 생략)")
    parser.add_argument("--base-rates", default="0.1,0.01", help="정밀도 환산에 가정할 공격 비율(쉼표 구분)")
    args = parser.parse_args()

    status_mode = args.waf_mode == "status"
    block_status = {code.strip() for code in args.block_status.split(",") if code.strip()}
    ai_urls = [url.strip().rstrip("/") for url in args.ai_url.split(",") if url.strip()]
    suspect_sources = [s.strip() for s in args.suspect_benign_sources.split(",") if s.strip()]
    base_rates = [float(v) for v in args.base_rates.split(",") if v.strip()]
    if status_mode and not args.skip_db:
        print("[info] status 모드는 메인 파이프라인을 거치지 않으므로 DB 확인을 건너뛴다")
        args.skip_db = True
    if status_mode:
        waf_note = f"차단 응답 {','.join(sorted(block_status))} ({args.waf_host}:{args.waf_port})"
        waf_note += (f", 기준선 {args.baseline_host}:{args.baseline_port}와 비교" if args.baseline_port
                     else ", 기준선 없음(앱 자체의 차단 코드도 탐지로 집계)")
    else:
        waf_note = (f"감사 로그의 요청 이상 점수({INBOUND_SCORE_RULE}) {INBOUND_THRESHOLD} 이상 또는 커스텀 룰(1000x) 매칭"
                    " (응답 단계 점수는 세지 않음)")

    samples = load_samples(args.input, args.limit)
    population = load_population(args.input)
    fingerprint = check_ai_ready(ai_urls)
    run_id = "r" + datetime.now().strftime("%m%d%H%M%S")
    requests_ = [build_request(s, run_id) for s in samples]
    print(f"run_id={run_id}, {len(samples)}건 전송 시작", flush=True)

    def summarize(codes):
        return Counter(s[:1] + 'xx' if s.isdigit() else s for s in codes)

    statuses = send_all(requests_, args.waf_host, args.waf_port, args.workers, "WAF 전송")
    baselines = [None] * len(requests_)
    if status_mode and args.baseline_port:
        baselines = send_all(requests_, args.baseline_host, args.baseline_port, args.workers, "기준선 전송")
    print(f"전송 완료: {summarize(statuses)}")
    server_errors = sum(s.startswith("5") for s in statuses)
    if server_errors > len(statuses) * 0.01:
        print(f"[warn] WAF 응답 5xx가 {server_errors}건이다. 백엔드가 멈췄는지 확인한다", flush=True)
    if status_mode:
        print(f"차단 응답({','.join(sorted(block_status))}): {sum(s in block_status for s in statuses)}건")
        if args.baseline_port:
            print(f"기준선 전송 완료: {summarize(baselines)}")

    ai_results = call_ai(requests_, ai_urls, args.ai_cache, fingerprint)
    sent_ok = sum(not s.startswith("ERR") for s in statuses)
    if status_mode:
        waf = status_verdicts(samples, statuses, baselines, block_status)
    else:
        time.sleep(3)  # Fluent Bit flush 대기
        waf = read_waf_audit(run_id)
    db = {} if args.skip_db else wait_until_stable(
        lambda: read_pipeline_db(run_id, args.db_container), sent_ok, 120, "DB 저장")

    rows = []
    for index, (sample, status, baseline) in enumerate(zip(samples, statuses, baselines), start=1):
        ai = ai_results.get(index)
        sid = sample["sample_id"]
        w = waf.get(sid, {"rules": [], "score": None, "block": False})
        families = sample["label_families"]
        rows.append({
            "sample_id": sid, "source": sample["source"], "label": sample["label_binary"],
            "family": families[0] if families else ("benign" if sample["label_binary"] == 0 else "unlabeled"),
            "method": sample["method"], "status": status, "send_error": status.startswith("ERR"),
            "baseline_status": baseline, "waf_ambiguous": w.get("ambiguous", False),
            "waf_detected": w["block"], "waf_any": bool(w["rules"]), "waf_score": w["score"],
            "waf_outbound_score": w.get("outbound_score"),
            "waf_rules": " ".join(sorted(set(w["rules"]))),
            "ai_error": ai is None,
            "ai_attack": None if ai is None else ai["ip_address"] != "0.0.0.0",
            "ai_score": None if ai is None else ai["threat_score"],
            "ai_reason": "" if ai is None else ai["reason"],
            "db_threats": db.get(sid) if not args.skip_db else None,
        })

    args.out_dir.mkdir(parents=True, exist_ok=True)
    out_csv, out_report = args.out_dir / "results.csv", args.out_dir / "report.md"
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    report = build_report(rows, args.label, waf_note, population, suspect_sources, base_rates)
    out_report.write_text(report, encoding="utf-8")
    print(report)
    print(f"\n저장: {out_csv}, {out_report}")


if __name__ == "__main__":
    main()
