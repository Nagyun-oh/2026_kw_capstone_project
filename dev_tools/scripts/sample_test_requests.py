"""test.jsonl에서 파이프라인 테스트용 요청을 뽑는다.

- 입력 : dev_tools/datasets/test.jsonl (Git 제외 대상)
- 출력 : dev_tools/datasets/sample.jsonl (Git 제외 대상)
         같은 이름의 .meta.json에 원본 구성(층별 건수)과 제외 건수를 남긴다.
         run_pipeline_test.py가 이 값으로 전체 탐지율·오탐률을 원본 비율에 맞춰 환산한다.
- 층(strata): (정상/공격, 출처, 대표 공격 유형)
- 제외 : URL 길이 > --max-url-len, 본문 > --max-body-len
         (WAF CUSTOM-001 룰 10002/10003이 길이만으로 차단하므로, AI 판단 비교에서는 뺀다.)

뽑는 방식(--mode)
- stratified(기본): 층마다 비슷한 개수를 뽑아 희귀 유형도 포함한다. 전체 수치는 이 배분대로 가중된다.
- census       : 공격은 전부 쓰고, 정상은 출처별로 --benign-cap건까지 무작위로 뽑는다.
                 공격 쪽은 원본 구성 그대로라 전체 탐지율이 배분에 영향받지 않는다.
                 중복 제거(--dedupe)를 함께 적용한다.
- --dedupe     : method·경로·쿼리·본문이 같은 요청은 처음 것만 남긴다. 같은 요청이 정상·공격 라벨로
                 함께 들어 있으면(라벨 충돌) 어느 탐지기든 한쪽은 틀리게 되므로 모두 뺀다.

사용 예:
    python dev_tools/scripts/sample_test_requests.py --total 3000 --seed 42
    python dev_tools/scripts/sample_test_requests.py --mode census --benign-cap 18000 --seed 42 \\
        --output dev_tools/datasets/sample-census.jsonl
"""
import argparse
import hashlib
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = PROJECT_ROOT / "dev_tools" / "datasets"

KEEP_FIELDS = ("method", "path", "query", "headers", "body", "content_type")


def request_url_length(record: dict) -> int:
    path = record.get("path") or ""
    query = record.get("query") or ""
    return len(path) + (1 + len(query) if query else 0)


def stratum_of(record: dict) -> tuple:
    label = int(record["label_binary"])
    families = record.get("label_families") or []
    if label == 0:
        family = "benign"
    else:
        family = families[0] if families else "unlabeled"
    return (label, record["source"], family)


def request_key(record: dict) -> str:
    """중복·라벨 충돌 판단 기준. 헤더는 출처마다 형식이 달라 넣지 않는다."""
    fields = [record.get(name) for name in ("method", "path", "query", "body")]
    return hashlib.sha256(json.dumps(fields, ensure_ascii=False).encode("utf-8")).hexdigest()


def allocate(sizes: dict, budget: int) -> dict:
    """각 층에 균등 배분하고, 층이 모자라면 남은 몫을 다른 층에 나눠 준다."""
    alloc = {k: 0 for k in sizes}
    open_keys = [k for k, n in sizes.items() if n > 0]
    while budget > 0 and open_keys:
        share = max(budget // len(open_keys), 1)
        next_open = []
        for key in open_keys:
            take = min(share, sizes[key] - alloc[key], budget)
            alloc[key] += take
            budget -= take
            if alloc[key] < sizes[key]:
                next_open.append(key)
        open_keys = next_open
    return alloc


def read_records(args, excluded: Counter):
    """길이 제한을 통과한 레코드를 차례로 돌려준다."""
    with open(args.input, encoding="utf-8", newline="\n") as f:
        for line in f:
            if not line.strip():
                continue
            record = json.loads(line)["record"]
            if request_url_length(record) > args.max_url_len:
                excluded["url_too_long"] += 1
                continue
            if len((record.get("body") or "").encode("utf-8")) > args.max_body_len:
                excluded["body_too_large"] += 1
                continue
            yield record


def find_label_conflicts(args) -> set:
    """정상·공격 라벨이 모두 붙은 요청의 key. 본 처리 전에 파일을 한 번 더 읽는다."""
    labels = defaultdict(set)
    for record in read_records(args, Counter()):
        labels[request_key(record)].add(int(record["label_binary"]))
    return {key for key, found in labels.items() if len(found) > 1}


def unique_records(args, excluded: Counter):
    """--dedupe일 때 라벨 충돌과 중복을 뺀 레코드를 돌려준다."""
    if not args.dedupe:
        yield from read_records(args, excluded)
        return
    conflicts = find_label_conflicts(args)
    seen = set()
    for record in read_records(args, excluded):
        key = request_key(record)
        if key in conflicts:
            excluded["label_conflict"] += 1
            continue
        if key in seen:
            excluded["duplicate"] += 1
            continue
        seen.add(key)
        yield record


def select_stratified(args, rng, excluded: Counter, population: Counter) -> list:
    reservoir_cap = args.total  # 층당 보관 한도. 메모리를 제한하려고 저수지 샘플링을 쓴다.
    reservoirs = defaultdict(list)
    for record in unique_records(args, excluded):
        key = stratum_of(record)
        population[key] += 1
        bucket = reservoirs[key]
        if len(bucket) < reservoir_cap:
            bucket.append(record)
        else:
            j = rng.randrange(population[key])
            if j < reservoir_cap:
                bucket[j] = record

    benign_budget = round(args.total * args.benign_ratio)
    chosen = []
    for label, budget in ((0, benign_budget), (1, args.total - benign_budget)):
        sizes = {k: len(v) for k, v in reservoirs.items() if k[0] == label}
        for key, take in allocate(sizes, budget).items():
            chosen.extend(rng.sample(reservoirs[key], take))
    return chosen


def select_census(args, rng, excluded: Counter, population: Counter) -> list:
    attacks = []
    reservoirs = defaultdict(list)   # 정상 출처별 저수지
    benign_seen = Counter()
    for record in unique_records(args, excluded):
        key = stratum_of(record)
        population[key] += 1
        if key[0] == 1:
            attacks.append(record)
            continue
        source = key[1]
        benign_seen[source] += 1
        bucket = reservoirs[source]
        if len(bucket) < args.benign_cap:
            bucket.append(record)
        else:
            j = rng.randrange(benign_seen[source])
            if j < args.benign_cap:
                bucket[j] = record
    return attacks + [record for source in sorted(reservoirs) for record in reservoirs[source]]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DATASET_DIR / "test.jsonl")
    parser.add_argument("--output", type=Path, default=DATASET_DIR / "sample.jsonl")
    parser.add_argument("--mode", choices=("stratified", "census"), default="stratified")
    parser.add_argument("--total", type=int, default=3000, help="stratified 모드의 전체 건수")
    parser.add_argument("--benign-ratio", type=float, default=0.4, help="stratified 모드의 정상 요청 비율")
    parser.add_argument("--benign-cap", type=int, default=18000, help="census 모드에서 정상 출처별 최대 건수")
    parser.add_argument("--dedupe", action="store_true", help="중복과 라벨 충돌 요청을 뺀다(census는 항상 적용)")
    parser.add_argument("--max-url-len", type=int, default=500)
    parser.add_argument("--max-body-len", type=int, default=10240)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if args.mode == "census":
        args.dedupe = True

    rng = random.Random(args.seed)
    excluded = Counter()
    population = Counter()   # 제외 뒤 원본에 남은 층별 건수(전체 수치 환산에 쓴다)
    select = select_census if args.mode == "census" else select_stratified
    chosen = select(args, rng, excluded, population)
    rng.shuffle(chosen)

    summary = Counter()
    width = max(5, len(str(len(chosen))))
    with open(args.output, "w", encoding="utf-8") as out:
        for i, record in enumerate(chosen, start=1):
            item = {
                "sample_id": f"s{i:0{width}d}",
                "source": record["source"],
                "record_id": record["record_id"],
                "label_binary": int(record["label_binary"]),
                "label_families": record.get("label_families") or [],
            }
            item.update({name: record.get(name) for name in KEEP_FIELDS})
            out.write(json.dumps(item, ensure_ascii=False) + "\n")
            summary[stratum_of(record)] += 1

    meta_path = args.output.with_name(args.output.stem + ".meta.json")
    meta = {
        "mode": args.mode, "seed": args.seed, "dedupe": args.dedupe,
        "total": args.total if args.mode == "stratified" else None,
        "benign_ratio": args.benign_ratio if args.mode == "stratified" else None,
        "benign_cap": args.benign_cap if args.mode == "census" else None,
        "max_url_len": args.max_url_len, "max_body_len": args.max_body_len,
        "excluded": dict(excluded),
        # [label, source, family, 원본 건수, 샘플 건수]
        "strata": [[*key, population[key], summary[key]] for key in sorted(population)],
    }
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    attacks = sum(n for key, n in summary.items() if key[0] == 1)
    print(f"written {len(chosen)} (공격 {attacks}, 정상 {len(chosen) - attacks}) -> {args.output}")
    print(f"meta -> {meta_path}")
    print(f"excluded: {dict(excluded)}")
    print("label x source x family: 샘플/원본")
    for key in sorted(population):
        print(f"  {key}: {summary[key]}/{population[key]}")


if __name__ == "__main__":
    main()
