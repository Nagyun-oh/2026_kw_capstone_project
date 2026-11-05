"""AI 호출 방식별 처리량·CPU 비교. 메인 스택과 분리한 실험용 AI 컨테이너에 쓴다(Kafka에 붙지 않게 한다).

  docker run -d --rm --name ai-diag -p 127.0.0.1:8101:8000 -e KAFKA_BOOTSTRAP_SERVERS=127.0.0.1:1 \
      [-e OMP_NUM_THREADS=1] security-ai:local
  python3 dev_tools/load-test/ai_threads.py http://127.0.0.1:8101 ai-diag
  docker stop ai-diag

묶음(/predict/batch, 100건씩), 한 건씩(/predict, 순차), 한 건씩 4개 동시 호출, 다시 묶음 순서로 census 샘플을 보내
초당 처리 건수와 1건당 CPU 시간(작업 구간의 docker stats 평균 CPU% × 시간 / 건수)을 잰다.
마지막 묶음 호출은 여러 스레드에서 호출한 뒤에도 속도가 유지되는지 보는 단계다.
"""
import json, re, statistics, subprocess, sys, threading, time, urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "dev_tools/scripts"))
import run_pipeline_test as m

url, container = sys.argv[1], sys.argv[2]
samples = m.load_samples(ROOT / "dev_tools/datasets/sample-census.jsonl", 0)[30000:30600]
items = []
for i, s in enumerate(samples, 1):
    item = m.ai_input(m.build_request(s, "diag"))
    item["log_id"] = i
    items.append(item)


def post(path, payload):
    req = urllib.request.Request(url + path, json.dumps(payload).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as resp:
        return json.load(resp)


class CpuSampler(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.values, self.stop = [], threading.Event()

    def run(self):
        proc = subprocess.Popen(["docker", "stats", "--format", "{{.CPUPerc}}", container],
                                stdout=subprocess.PIPE, text=True)
        for line in proc.stdout:
            if self.stop.is_set():
                break
            hit = re.search(r"([\d.]+)%", line)     # 화면 제어 문자 사이의 "12.34%"
            if hit:
                self.values.append((time.time(), float(hit.group(1))))
        proc.kill()


def measure(name, fn, n):
    sampler = CpuSampler()
    sampler.start()
    time.sleep(2.5)
    t = time.time()
    fn()
    t_end = time.time()
    dt = t_end - t
    sampler.stop.set()
    inside = [c for ts, c in sampler.values if t + 1 <= ts <= t_end]     # 작업 구간 안의 값만
    cpu = statistics.fmean(inside) if inside else float("nan")
    print(f"  {name:<22} {n}건 {dt:6.1f}s  {n / dt:6.1f}건/s  CPU 평균 {cpu:5.0f}%  1건당 CPU {cpu / 100 * dt / n * 1000:6.1f}ms",
          flush=True)


post("/predict/batch", items[:20])     # 예열
measure("묶음 100건씩", lambda: [post("/predict/batch", items[i:i + 100]) for i in range(0, 600, 100)], 600)
measure("한 건씩 순차", lambda: [post("/predict", it) for it in items[:200]], 200)
with ThreadPoolExecutor(4) as pool:
    measure("한 건씩 4개 동시", lambda: list(pool.map(lambda it: post("/predict", it), items[200:400])), 200)
measure("묶음 100건씩(다시)", lambda: [post("/predict/batch", items[i:i + 100]) for i in range(0, 600, 100)], 600)
