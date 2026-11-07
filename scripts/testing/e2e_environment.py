"""E2E 대상 환경·허용 주소·결과 경로. 조회·HTTP·파일 생성은 하지 않는다."""
from dataclasses import dataclass
from pathlib import Path
import re
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[2]
ENVIRONMENTS = {
    "local": ("http://localhost/", "http://localhost:3000/"),
    "ec2": ("https://security-juiceshop-kw.duckdns.org/",
            "https://security-monitor-kw.duckdns.org/"),
}


def allowed_url(value, expected):
    """이 환경에 지정한 root origin만 허용한다. 오류에 입력 원문을 넣지 않는다."""
    try:
        if not isinstance(value, str) or any(c.isspace() for c in value) or "\\" in value:
            raise ValueError
        parsed, wanted = urlsplit(value), urlsplit(expected)
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        expected_port = wanted.port if wanted.port is not None else (443 if wanted.scheme == "https" else 80)
        if (parsed.username is not None or parsed.password is not None
                or parsed.scheme != wanted.scheme or parsed.hostname != wanted.hostname
                or port != expected_port or parsed.path not in ("", "/")
                or parsed.query or parsed.fragment or "?" in value or "#" in value
                or parsed.netloc.endswith(":")):
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError("환경의 허용 목록에 없는 URL입니다. HTTPS·호스트·포트·루트 경로를 확인하세요.") from None
    return expected


@dataclass(frozen=True)
class E2EEnvironment:
    name: str
    target_url: str
    dashboard_url: str

    def __post_init__(self):
        if self.name not in ENVIRONMENTS:
            raise ValueError("환경은 local 또는 ec2여야 합니다.")
        target, dashboard = ENVIRONMENTS[self.name]
        if self.target_url != allowed_url(self.target_url, target) or self.dashboard_url != allowed_url(self.dashboard_url, dashboard):
            raise ValueError("환경 URL은 정규화된 허용 주소여야 합니다.")

    @property
    def schema(self):
        return "local-e2e-v2" if self.name == "local" else "ec2-e2e-v1"

    @property
    def contract_path(self):
        return (ROOT / "docs/testing/local/e2e-plan-v2.json" if self.name == "local"
                else ROOT / "scripts/testing/profiles/ec2-e2e-v1.json")

    @property
    def execution_ready(self):
        # 일반 실행 경로는 로컬만 허용한다. EC2는 고정 계약을 검증하는 전용 실행기를 사용한다.
        return self.name == "local"

    @property
    def collection_mode(self):
        return "local_compose" if self.name == "local" else "ssh_read_only_collection"

    def require_execution_ready(self):
        if not self.execution_ready:
            raise ValueError("이 실행 경로는 EC2 부하를 지원하지 않습니다. 확정 계약과 원격 감시·원복을 연결한 scripts/testing/run_ec2_e2e.py를 사용하세요.")

    def probe_url(self, path):
        if (not isinstance(path, str) or not path.startswith("/") or path.startswith("//")
                or "\\" in path or re.search(r"[\x00-\x20\x7f]", path)):
            raise ValueError("요청 경로는 대상 origin 안의 절대 경로여야 합니다.")
        base = "http://127.0.0.1" if self.name == "local" else self.target_url.rstrip("/")
        return base + path

    def public_plan(self):
        return {
            "environment": self.name, "target_url": self.target_url,
            "dashboard_url": self.dashboard_url, "schema": self.schema,
            "transport": "ipv4_loopback_host_localhost" if self.name == "local" else "public_https_verified_tls",
            "tls_verification": self.name == "ec2", "collection_mode": self.collection_mode,
            "execution_ready": self.execution_ready,
            "report_directory": f"docs/testing/{self.name}/runs",
            "generator_location": "current_windows_pc",
            "cross_clock_policy": "local_100ms_existing" if self.name == "local" else "four_timestamp_offset_interval",
            "targets_status": "local_existing_contract" if self.name == "local" else "confirmed_ec2_contract_dedicated_runner",
        }


def select_environment(name="local", target_url=None, dashboard_url=None):
    if name not in ENVIRONMENTS:
        raise ValueError("환경은 local 또는 ec2여야 합니다.")
    target, dashboard = ENVIRONMENTS[name]
    return E2EEnvironment(name, allowed_url(target_url if target_url is not None else target, target),
                          allowed_url(dashboard_url if dashboard_url is not None else dashboard, dashboard))


def result_paths(root, run_id, environment="local"):
    if environment not in ENVIRONMENTS:
        raise ValueError("결과 경로의 환경은 local 또는 ec2여야 합니다.")
    if not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9_+.-]+", run_id) or run_id in (".", ".."):
        raise ValueError("실험 ID는 경로 구분자가 없는 파일명이어야 합니다.")
    root = Path(root)
    return (root / "build/test-runs" / run_id,
            root / "docs/testing" / environment / "runs" / (run_id + ".md"))
