"""전수 테스트셋을 실행 중인 WAF 랩(한 PL 설정)에 보내 PL 운영점(탐지율·오탐률)을 잰다.

WAF 단독(AI 호출 없음). ROC 그림에 PL별 점으로 올리기 위한 측정이다.
랩 기동은 바깥에서(탐지 PL ≥ 차단 PL):
    LAB_BLOCKING_PL=4 LAB_DETECTION_PL=4 docker compose -f wafs/docker-compose.yml up -d modsecurity
    python dev_tools/scripts/waf_pl_point.py --pl 4 --port 8090 \\
        --out dev_tools/datasets/roc-auc/waf-pl4.json
"""
import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_pipeline_test as rp  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--pl", required=True, help="PL 라벨(1~4) — 결과 표기용")
    ap.add_argument("--input", default=str(ROOT / "dev_tools/datasets/sample-raw-all.jsonl"))
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--workers", type=int, default=24)
    ap.add_argument("--block-status", default="403,406", help="차단(탐지)으로 볼 응답 코드")
    ap.add_argument("--out", required=True)
    ap.add_argument("--dump", default="", help="요청별 상태(sample_id,status) jsonl 경로(OR/AND 결합용)")
    a = ap.parse_args()

    block = set(a.block_status.split(","))
    samples = [json.loads(l) for l in open(a.input, encoding="utf-8") if l.strip()]
    reqs = [rp.build_request(s, f"pl{a.pl}") for s in samples]
    print(f"PL{a.pl}: {len(reqs)}건 → {a.host}:{a.port} (차단코드 {sorted(block)})", flush=True)

    t0 = time.time()
    statuses = rp.send_all(reqs, a.host, a.port, a.workers, f"WAF PL{a.pl}")

    att_t = att_d = ben_t = ben_d = 0
    by_src = defaultdict(lambda: [0, 0, 0, 0])  # [att_t, att_d, ben_t, ben_d]
    for s, st in zip(samples, statuses):
        det = st in block
        v = by_src[s.get("source", "?")]
        if s["label_binary"] == 1:
            att_t += 1; att_d += det; v[0] += 1; v[1] += det
        else:
            ben_t += 1; ben_d += det; v[2] += 1; v[3] += det

    out = {
        "pl": a.pl, "n": len(samples), "attack": att_t, "benign": ben_t,
        "detection": round(att_d / att_t, 4) if att_t else None,
        "fpr": round(ben_d / ben_t, 4) if ben_t else None,
        "detected_attacks": att_d, "detected_benign": ben_d,
        "status_dist": dict(Counter(statuses)),
        "by_source": {k: {"det": round(v[1] / v[0], 4) if v[0] else None,
                          "fpr": round(v[3] / v[2], 4) if v[2] else None} for k, v in sorted(by_src.items())},
        "elapsed": round(time.time() - t0),
    }
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    if a.dump:
        with open(a.dump, "w", encoding="utf-8") as fh:
            for s, st in zip(samples, statuses):
                fh.write(json.dumps({"sample_id": s["sample_id"], "status": st}) + "\n")
        print(f"상태 덤프: {a.dump}", flush=True)
    print(json.dumps({k: out[k] for k in ("pl", "n", "attack", "benign", "detection", "fpr", "elapsed")},
                     ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
