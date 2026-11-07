"""EC2 P0 읽기 전용 현황 수집. 서버에서 실행하고 JSON만 표준 출력으로 보낸다.

Python 표준 라이브러리만 사용한다. 앱 HTTP 요청·부하·재시작·DDL·데이터 변경은 없다.
명령의 원문 stderr, 환경 변수 값, DB 행 본문, Nginx 전체 설정은 결과에 넣지 않는다.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.request


SCHEMA = "dualguard-ec2-inventory-v1"
PROJECT = "security-platform-aws"
ENV_KEYS = (
    "IMAGE_REGISTRY_PREFIX", "IMAGE_TAG", "MYSQL_ROOT_PASSWORD", "DB_USERNAME",
    "DB_PASSWORD", "WAF_SYNC_TOKEN", "WAF_TRUSTED_PROXY", "WAF_CONSUMER_ENABLED",
    "WAF_EVENT_ZONE", "AI_OUTBOX_ENABLED", "PIPELINE_TRACE_ENABLED",
    "APP_BOOTSTRAP_ADMIN_ENABLED", "APP_BOOTSTRAP_ADMIN_USERNAME",
    "APP_BOOTSTRAP_ADMIN_PASSWORD",
)
TABLES = ("network_logs", "detected_threats", "waf_detections", "ip_blacklist",
          "request_alerts", "request_correlations", "waf_sync_status", "ai_request_outbox")
STREAMS = {("log-group", "log-topic"), ("ai-service-group", "ai-request-topic"),
           ("ai-result-group", "ai-result-topic"), ("waf-detection-group", "waf-detection-topic")}
HASH_FILES = (
    "compose.aws.yaml", "waf/nginx.conf.template", "waf/nginx-logging.conf.template",
    "waf/modsecurity.conf.template", "waf/njs/headers.js", "waf/sync/blacklist-sync.sh",
    "waf/rules/CUSTOM-003-blacklist-sync.conf", "AI_new/models.lock.json",
)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def env_presence(path):
    """dotenv를 실행/전개하지 않고 정해진 키의 존재 여부만 남긴다."""
    found = set()
    try:
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            match = re.match(r"^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=", line)
            if match:
                found.add(match[1])
    except OSError:
        return {"readable": False, "keys_present": None}
    return {"readable": True, "keys_present": {key: key in found for key in ENV_KEYS}}


def json_lines(text):
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def lag_rows(text):
    """CLI 표에서 HOST·consumer ID를 제거하고 오프셋·lag만 남긴다."""
    rows, header = [], None
    for line in text.splitlines():
        parts = line.split()
        if {"GROUP", "TOPIC", "PARTITION", "LAG"} <= set(parts):
            header = parts
        elif header and len(parts) >= len(header):
            values = dict(zip(header, parts))
            try:
                row = {k.lower().replace("-", "_"): None if values[k] == "-" else int(values[k])
                       for k in ("PARTITION", "CURRENT-OFFSET", "LOG-END-OFFSET", "LAG")}
                row.update(group=values["GROUP"], topic=values["TOPIC"])
                rows.append(row)
            except (KeyError, ValueError):
                continue
    return rows


def nginx_summary(text):
    """인증 정보·IP를 포함할 수 있는 설정 원문 대신 필요한 항목만 추출한다."""
    # 주소는 저장하지 않는다. P1에서 발생기 IP·차단 제외 정책을 별도로 결정한다.
    return {
        "sha256_of_config_stdout": hashlib.sha256(text.encode()).hexdigest(),
        "request_id_response_header_present": bool(re.search(r"(?im)^\s*(?:more_set_headers|add_header)\b[^\n]*X-Request-ID", text)),
        "request_start_response_header_present": bool(re.search(r"(?im)^\s*(?:more_set_headers|add_header)\b[^\n]*X-DualGuard-Request-Start", text)),
        "trusted_proxy_directive_count": len(re.findall(r"(?m)^\s*set_real_ip_from\s", text)),
        "real_ip_headers": sorted(set(re.findall(r"(?m)^\s*real_ip_header\s+([A-Za-z0-9_-]+)\s*;", text))),
        "real_ip_recursive": re.findall(r"(?m)^\s*real_ip_recursive\s+(on|off)\s*;", text),
        "forwarded_for_header_set": bool(re.search(r"(?m)^\s*proxy_set_header\s+X-Forwarded-For\s", text)),
        "websocket_upgrade_header_set": bool(re.search(r"(?im)^\s*proxy_set_header\s+Upgrade\s", text)),
        "upstream_ports": sorted(set(int(p) for p in re.findall(r"proxy_pass\s+https?://(?:127\.0\.0\.1|localhost):([0-9]+)", text))),
    }


class Collector:
    def __init__(self, repo):
        self.repo = Path(repo).resolve()
        self.commands = []
        self.data = {"schema": SCHEMA, "started_at": utc_now(), "scope": "P0_read_only_inventory",
                     "load_generated": False, "commands": self.commands}

    def run(self, label, argv, *, input_text=None, timeout=15):
        start = time.monotonic()
        item = {"check": label, "started_at": utc_now(), "timeout_seconds": timeout}
        try:
            result = subprocess.run(argv, cwd=self.repo, input=input_text, text=True,
                                    encoding="utf-8", errors="replace", capture_output=True,
                                    timeout=timeout, env={**os.environ, "AWS_PAGER": "",
                                                        "AWS_MAX_ATTEMPTS": "1"})
            item.update(exit_code=result.returncode, status="OK" if result.returncode == 0 else "COMMAND_FAILED")
            # 실패 원문에 접속 정보·비밀값이 포함될 수 있어 stderr는 보존하지 않는다.
            return result.stdout if result.returncode == 0 else None
        except subprocess.TimeoutExpired:
            item["status"] = "TIMEOUT"
        except OSError:
            item["status"] = "UNAVAILABLE"
        finally:
            item["elapsed_ms"] = round((time.monotonic() - start) * 1000, 3)
            self.commands.append(item)
        return None

    def parse(self, label, text, parser):
        if text is None:
            return None
        try:
            return parser(text)
        except (ValueError, KeyError, TypeError):
            self.data.setdefault("parse_errors", []).append(label)
            return None

    def docker(self, label, args, **kwargs):
        return self.run(label, ["sudo", "-n", "docker", *args], **kwargs)

    def sql(self, label, container, sql):
        # 비밀번호는 컨테이너 안에서만 환경 변수로 전달한다. 호스트 argv·JSON에는 넣지 않는다.
        for method, auth in (("app", 'MYSQL_PWD="$MYSQL_PASSWORD" exec mysql -u "$MYSQL_USER"'),
                             ("root", 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql -u root')):
            text = self.docker(label + "_" + method, ["exec", "-i", container, "sh", "-c",
                auth + " -D security_db --batch --raw --skip-column-names --connect-timeout=3"],
                input_text="SET SESSION MAX_EXECUTION_TIME=3000;\nSTART TRANSACTION READ ONLY;\n" + sql + "\nROLLBACK;\n", timeout=12)
            if text is not None:
                self.data.setdefault("database_auth", {})[label] = method + "_container_environment"
                return self.parse(label, text, json_lines)
        return None

    def collect(self, include_cloudwatch=False):
        for key, args in (("sha", ["git", "rev-parse", "HEAD"]),
                          ("changed_files", ["git", "status", "--short"]),
                          ("docker_version", ["sudo", "-n", "docker", "version", "--format", "{{.Server.Version}}"]),
                          ("compose_version", ["sudo", "-n", "docker", "compose", "version", "--short"])):
            text = self.run(key, args)
            self.data[key] = text.strip() if text is not None else None
        self.data["env_file"] = env_presence(self.repo / ".env.aws")
        self.data["file_sha256"] = {}
        for rel in HASH_FILES:
            path = self.repo / rel
            self.data["file_sha256"][rel] = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
        self.host()
        ids = (self.docker("project_containers", ["ps", "-aq", "--filter", "label=com.docker.compose.project=" + PROJECT]) or "").split()
        ids = [value for value in ids if re.fullmatch(r"[a-f0-9]{12,64}", value)]
        # healthcheck가 없는 컨테이너에는 Health 키 자체가 없을 수 있다.
        template = '{"service":{{json (index .Config.Labels "com.docker.compose.service")}},"image":{{json .Config.Image}},"image_id":{{json .Image}},"state":{{json .State.Status}},"health":{{with index .State "Health"}}{{json .Status}}{{else}}null{{end}},"exit_code":{{.State.ExitCode}},"restart_count":{{.RestartCount}},"started_at":{{json .State.StartedAt}},"memory_limit_bytes":{{.HostConfig.Memory}},"nano_cpus":{{.HostConfig.NanoCpus}},"log_driver":{{json .HostConfig.LogConfig.Type}}}'
        self.data["containers"] = []
        by_service = {}
        for cid in ids:
            parsed = self.parse("container", self.docker("container_inspect", ["inspect", "--format", template, cid]), json.loads)
            if parsed is None:
                continue
            by_service[parsed["service"]] = cid
            parsed["image"] = parsed["image"].rsplit("/", 1)[-1]
            digests = self.parse("image_digests", self.docker("image_digests", ["image", "inspect", "--format", "{{json .RepoDigests}}", parsed["image_id"]]), json.loads)
            parsed["repo_digests_registry_removed"] = [s.rsplit("/", 1)[-1] for s in (digests or [])]
            self.data["containers"].append(parsed)
        backend = by_service.get("backend")
        if backend:
            self.data["runtime_flags"] = {}
            for name in ("AI_OUTBOX_ENABLED", "PIPELINE_TRACE_ENABLED", "WAF_CONSUMER_ENABLED"):
                value = self.docker("runtime_" + name, ["exec", backend, "printenv", name])
                self.data["runtime_flags"][name] = value.strip().lower() == "true" if value and value.strip().lower() in ("true", "false") else None
        db = by_service.get("db")
        if db:
            self.database(db)
        kafka = by_service.get("kafka")
        self.data["kafka_lag"] = self.parse("kafka_lag", self.docker("kafka_lag", ["exec", kafka, "kafka-consumer-groups", "--bootstrap-server", "kafka:29092", "--all-groups", "--describe"], timeout=25), lag_rows) if kafka else None
        self.data["nginx"] = {}
        self.data["nginx"]["host"] = self.parse("host_nginx", self.run("host_nginx", ["sudo", "-n", "nginx", "-T"]), nginx_summary)
        waf = by_service.get("waf")
        if waf:
            self.data["nginx"]["waf"] = self.parse("waf_nginx", self.docker("waf_nginx", ["exec", waf, "nginx", "-T"]), nginx_summary)
        self.cloud(include_cloudwatch)
        missing = [key for key in ("sha", "containers", "database", "kafka_lag") if not self.data.get(key)]
        tables_found = {r.get("table") for r in (self.data.get("database") or []) if r.get("kind") == "table"}
        missing.extend("table:" + name for name in TABLES if name not in tables_found)
        streams_found = {(r["group"], r["topic"]) for r in (self.data.get("kafka_lag") or []) if r["lag"] is not None}
        missing.extend("lag:" + group + "/" + topic for group, topic in sorted(STREAMS - streams_found))
        if not self.data["env_file"]["readable"]:
            missing.append("env_key_presence")
        if not self.data.get("runtime_flags") or any(v is None for v in self.data["runtime_flags"].values()):
            missing.append("runtime_flags")
        for layer in ("host", "waf"):
            if not self.data["nginx"].get(layer):
                missing.append(layer + "_nginx")
        if self.data["ec2"]["metadata_status"] != "OK":
            missing.append("ec2_metadata")
        if not self.data.get("clock", {}).get("chrony"):
            missing.append("chrony")
        if self.data["ec2"].get("credits_status") in (None, "NOT_REQUESTED", "UNCONFIRMED"):
            missing.append("cpu_credits")
        self.data.update(ended_at=utc_now(), missing_observations=missing,
                         inventory_status="COLLECTED_WITH_GAPS" if missing or any(c["status"] != "OK" for c in self.commands) or self.data.get("parse_errors") else "COLLECTED")
        self.data["limitations"] = [
            "환경 현황의 단일 표본이며 성능·E2E·장애 검증 PASS 판정이 아니다.",
            "TABLE_ROWS는 추정치다. 데이터·계정·환경 값·전체 Nginx 설정은 저장하지 않았다.",
            "명령 시각은 순차 수집 시각이다. 조회 실패·빈 출력·미측정을 0으로 치환하지 않는다.",
            "로컬 체크아웃 SHA와 실행 중인 이미지 태그·digest는 각각 확인한다.",
            "앱 HTTP·probe·관리자 로그인·모델 파일 전체 무결성 검사는 수행하지 않았다."]
        return self.data

    def host(self):
        mem = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, value = line.split(":", 1)
            if key in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"):
                mem[key + "_bytes"] = int(value.split()[0]) * 1024
        disk = shutil.disk_usage(self.repo)
        self.data["host"] = {"logical_cpus": os.cpu_count(), "memory": mem,
                             "load_average": os.getloadavg(), "disk_bytes": dict(total=disk.total, used=disk.used, free=disk.free)}
        lscpu = self.parse("lscpu", self.run("lscpu", ["lscpu", "--json"]), json.loads)
        self.data["host"]["cpu"] = [x for x in lscpu.get("lscpu", []) if x.get("field") in ("Architecture:", "CPU(s):", "Model name:", "Thread(s) per core:", "Core(s) per socket:")] if lscpu else None
        self.data["clock"] = {}
        chrony = self.run("chrony_tracking", ["chronyc", "tracking"])
        self.data["clock"]["chrony"] = [line.strip() for line in chrony.splitlines() if line.split(":", 1)[0].strip() in ("System time", "Last offset", "RMS offset", "Stratum", "Leap status")] if chrony else None
        self.data["clock"]["timedatectl"] = self.run("timedatectl", ["timedatectl", "show", "--property=NTPSynchronized", "--property=Timezone"])

    def database(self, cid):
        names = ",".join("'" + name + "'" for name in TABLES)
        rows = self.sql("schema", cid, f"""
SELECT JSON_OBJECT('kind','clock','version',VERSION(),'now_raw',CAST(NOW(6) AS CHAR),'utc_now',CAST(UTC_TIMESTAMP(6) AS CHAR),'session_time_zone',@@session.time_zone,'global_time_zone',@@global.time_zone);
SELECT JSON_OBJECT('kind','table','table',TABLE_NAME,'estimated_rows',TABLE_ROWS,'data_bytes',DATA_LENGTH,'index_bytes',INDEX_LENGTH)
FROM information_schema.TABLES WHERE TABLE_SCHEMA='security_db' AND TABLE_NAME IN ({names});
SELECT JSON_OBJECT('kind','column','table',TABLE_NAME,'column',COLUMN_NAME,'type',COLUMN_TYPE,'collation',COLLATION_NAME,'nullable',IS_NULLABLE)
FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='security_db' AND TABLE_NAME IN ({names}) AND COLUMN_NAME IN ('id','request_id','threat_id','log_id','alert_key','alert_id','request_url','state','available_at','published_at');
SELECT JSON_OBJECT('kind','unique','table',TABLE_NAME,'name',INDEX_NAME,'columns',GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX))
FROM information_schema.STATISTICS WHERE TABLE_SCHEMA='security_db' AND TABLE_NAME IN ({names}) AND NON_UNIQUE=0 GROUP BY TABLE_NAME,INDEX_NAME;
SELECT JSON_OBJECT('kind','foreign_key','table',TABLE_NAME,'column',COLUMN_NAME,'references_table',REFERENCED_TABLE_NAME,'references_column',REFERENCED_COLUMN_NAME)
FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA='security_db' AND TABLE_NAME IN ({names}) AND REFERENCED_TABLE_NAME IS NOT NULL;
""")
        self.data["database"] = rows
        if rows and any(row.get("kind") == "table" and row.get("table") == "ai_request_outbox" for row in rows):
            self.data["outbox_counts"] = self.sql("outbox_counts", cid, "SELECT /*+ MAX_EXECUTION_TIME(3000) */ JSON_OBJECT('state',state,'count',COUNT(*)) FROM ai_request_outbox GROUP BY state;")
        else:
            self.data["outbox_counts"] = None

    def cloud(self, include_cloudwatch):
        self.data["ec2"] = {"metadata_status": "UNAVAILABLE", "credits": None}
        start = time.monotonic()
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            token = opener.open(urllib.request.Request("http://169.254.169.254/latest/api/token", method="PUT", headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"}), timeout=2).read().decode()
            doc = json.load(opener.open(urllib.request.Request("http://169.254.169.254/latest/dynamic/instance-identity/document", headers={"X-aws-ec2-metadata-token": token}), timeout=2))
            self.data["ec2"].update(metadata_status="OK", instance_type=doc["instanceType"], region=doc["region"], architecture=doc.get("architecture"))
            instance_id, region = doc["instanceId"], doc["region"]
        except Exception:
            # IMDS 토큰·계정 ID·실 IP와 예외 원문은 보존하지 않는다.
            return
        finally:
            self.data["ec2"]["metadata_elapsed_ms"] = round((time.monotonic() - start) * 1000, 3)
        if not include_cloudwatch or not re.match(r"^t[234]", doc["instanceType"]):
            self.data["ec2"]["credits_status"] = "NOT_REQUESTED" if not include_cloudwatch else "NOT_APPLICABLE"
            return
        prefix = ["aws", "--region", region, "--cli-connect-timeout", "3", "--cli-read-timeout", "5", "--output", "json"]
        mode = self.parse("credit_mode", self.run("credit_mode", prefix + ["ec2", "describe-instance-credit-specifications", "--instance-ids", instance_id]), json.loads)
        end = datetime.now(timezone.utc)
        credit = self.parse("credit_balance", self.run("credit_balance", prefix + ["cloudwatch", "get-metric-statistics", "--namespace", "AWS/EC2", "--metric-name", "CPUCreditBalance", "--dimensions", "Name=InstanceId,Value=" + instance_id, "--start-time", (end - timedelta(minutes=30)).isoformat(), "--end-time", end.isoformat(), "--period", "300", "--statistics", "Average"]), json.loads)
        self.data["ec2"]["credits"] = {
            "mode": next((x.get("CpuCredits") for x in mode.get("InstanceCreditSpecifications", []) if x.get("InstanceId") == instance_id), None) if mode else None,
            "balance_datapoints": sorted(credit.get("Datapoints", []), key=lambda p: p["Timestamp"]) if credit else None,
            "period_seconds": 300, "lookback_minutes": 30}
        self.data["ec2"]["credits_status"] = "OBSERVED" if mode and credit and credit.get("Datapoints") else "UNCONFIRMED"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--include-cloudwatch", action="store_true", help="기존 권한의 AWS CLI로 조회한다. 실패해도 IAM은 변경하지 않는다.")
    args = parser.parse_args(argv)
    if sys.platform != "linux" or not (args.repo / "compose.aws.yaml").is_file():
        parser.error("EC2 Linux의 저장소를 --repo로 지정해야 한다. 로컬에서는 실행하지 않는다.")
    print(json.dumps(Collector(args.repo).collect(args.include_cloudwatch), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
