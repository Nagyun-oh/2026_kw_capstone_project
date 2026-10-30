#!/usr/bin/env python3
"""AI_new/models.lock.json에 고정된 모델 파일을 Kaggle에서 받아 SHA-256으로 검증한다.

- 데이터셋 전체(약 1.3GB)가 아니라 lock에 적힌 파일만 버전을 지정해 받는다.
- 해시가 일치하는 파일이 이미 있으면 다시 받지 않는다.
- 해시가 다르면 파일을 저장하지 않고 실패한다. (.pkl은 로드 시 임의 코드를 실행할 수 있음)

CI, CD, EC2 수동 배포에서 공통으로 사용한다. Python 표준 라이브러리만 사용한다.

사용법 (저장소 루트에서):
    python3 scripts/fetch_models.py
    python3 scripts/fetch_models.py --lock AI_new/models.lock.json
"""

import argparse
import hashlib
import json
import os
import sys
import tempfile
import urllib.request
from pathlib import Path

KAGGLE_DOWNLOAD_URL = "https://www.kaggle.com/api/v1/datasets/download/{dataset}/{name}?datasetVersionNumber={version}"
CHUNK_SIZE = 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_verified(url: str, dest: Path, expected_sha256: str) -> None:
    """임시 파일로 받은 뒤 해시가 일치할 때만 dest로 옮긴다."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=dest.parent, prefix=".download-")
    tmp_path = Path(tmp_name)
    try:
        digest = hashlib.sha256()
        with os.fdopen(fd, "wb") as out, urllib.request.urlopen(url, timeout=60) as resp:
            for chunk in iter(lambda: resp.read(CHUNK_SIZE), b""):
                out.write(chunk)
                digest.update(chunk)
        actual = digest.hexdigest()
        if actual != expected_sha256:
            raise ValueError(f"SHA-256 불일치: expected={expected_sha256} actual={actual}")
        tmp_path.chmod(0o644)
        tmp_path.replace(dest)
    finally:
        tmp_path.unlink(missing_ok=True)


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--lock", type=Path, default=repo_root / "AI_new" / "models.lock.json")
    args = parser.parse_args()

    lock = json.loads(args.lock.read_text(encoding="utf-8"))
    base_dir = args.lock.resolve().parent
    print(f"[models] {lock['dataset']} v{lock['version']}")

    failed = False
    for entry in lock["files"]:
        dest = base_dir / entry["path"]
        expected = entry["sha256"].lower()

        if dest.is_file() and sha256_file(dest) == expected:
            print(f"  OK (cached)  {entry['path']}")
            continue

        url = KAGGLE_DOWNLOAD_URL.format(dataset=lock["dataset"], name=entry["name"], version=lock["version"])
        try:
            download_verified(url, dest, expected)
            print(f"  OK           {entry['path']}")
        except Exception as e:
            print(f"  FAILED       {entry['path']}: {e}", file=sys.stderr)
            failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
