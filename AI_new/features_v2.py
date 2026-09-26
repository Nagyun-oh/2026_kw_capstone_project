# -*- coding: utf-8 -*-
"""
features_v2.py — 학습과 서빙이 공유하는 단일 피처 정의 (train/serving skew 방지)

v1 대비 변경점
  1. user_agent 문자열 인코딩 제거 → 출처 지름길(source shortcut) 차단.
     UA는 봇 여부 / 비어있음 두 개의 이진 신호로만 사용.
  2. 키워드 목록 보강 — v1은 대표 페이로드 15개 중 8개(53%)를 전혀 못 봤음.
     특히 `' OR 1=1--` 류 토톨로지 SQLi는 정규식으로 별도 탐지.
  3. v1의 오탐 원인 제거 — XSS 키워드의 맨몸 "script"는
     "description" 같은 평범한 단어에도 매칭됨("de-script-ion"). 제거.
  4. 헤더 기반 피처(n_headers/header_bytes/content_type) 제거 —
     WAF access.log에 없어 운영에서 계산 불가 + 출처 지름길로 작동했음.
  5. body가 없어도(운영 현재 상태) 동일하게 동작하도록 설계.
"""
import re
from urllib.parse import unquote

MAX_SCAN = 65_536          # 초대형 body 방어 (길이 피처는 실제 길이 사용)

# ── 문자 집합
SPECIAL_CHARS = ["'", '"', "<", ">", "--", ";", "%", "(", ")", "="]

# ── SQL: 함수/구문 기반 (v1 11개 → 확장)
SQL_KEYWORDS = [
    "select", "insert", "update", "delete", "drop", "union", "where", "from",
    "exec", "sleep", "benchmark", "having", "truncate", "alter", "create",
    "information_schema", "table_name", "column_name", "xp_cmdshell",
    "load_file", "outfile", "dumpfile", "waitfor", "pg_sleep", "dbms_pipe",
    "utl_http", "@@version", "version()", "database()", "user()", "concat(",
    "char(", "cast(", "convert(", "substring(", "ascii(", "hex(", "unhex(",
    "group_concat", "order by", "group by",
]
# ── SQL: 토톨로지 / 논리 우회 (v1이 완전히 놓치던 영역)
SQL_TAUTOLOGY_RE = re.compile(
    r"""(['"]?\s*\b(or|and)\b\s*['"]?[\w.]+['"]?\s*(=|<>|!=|<|>|\blike\b)\s*['"]?[\w.]+['"]?)"""
    r"""|(\b(or|and)\s+\d+\s*=\s*\d+)"""
    r"""|(['"]\s*(or|and)\s*['"])""",
    re.IGNORECASE)
SQL_COMMENT_RE = re.compile(r"(--\s|--$|/\*|\*/|;--|#$)")

# ── XSS: 맨몸 "script" 제거, 태그/핸들러/프로토콜로 정밀화
XSS_KEYWORDS = [
    "<script", "</script", "javascript:", "vbscript:", "data:text/html",
    "<img", "<svg", "<iframe", "<object", "<embed", "<body", "<marquee",
    "<details", "<video", "<audio", "srcdoc", "document.cookie", "document.write",
    "window.location", "eval(", "atob(", "fromcharcode", "expression(",
    "alert(", "prompt(", "confirm(",
]
QUOTE_COMMENT_RE = re.compile(r"""['"][\s)]*--""")          # ' -- , ';  → SQLi 종결 패턴
UNION_SELECT_RE  = re.compile(r"\bunion\b(\s+all)?\s+\bselect\b", re.IGNORECASE)
SQL_STMT_RE = re.compile(r"\b(drop\s+table|delete\s+from|insert\s+into|update\s+\w+\s+set|"
                         r"truncate\s+table|alter\s+table|xp_cmdshell|load_file\s*\(|"
                         r"into\s+(out|dump)file|information_schema\.)", re.IGNORECASE)
SSTI_RE = re.compile(r"\{\{\s*[\w.\[\]'\"]*\s*[*+\-/]\s*[\w.'\"]|\{\{\s*(config|self|request|__)")
LOG4SHELL_RE = re.compile(r"\$\{\s*(jndi|env|sys|lower|upper|date)\s*:", re.IGNORECASE)
XSS_EVENT_RE = re.compile(r"\bon(error|load|click|mouseover|focus|blur|submit|"
                          r"change|keyup|keydown|toggle|animationstart|start)\s*=", re.IGNORECASE)

# ── Path Traversal / LFI
PATH_TRAVERSAL_PATTERNS = [
    "../", "..\\", "%2e%2e", "..%2f", "..%5c", "%252e", "..;/",
    "etc/passwd", "etc/shadow", "boot.ini", "win.ini", "/proc/self",
    "web.config", "wp-config", ".ssh/id_rsa", "/.env",
]
# ── 커맨드 인젝션
CMD_KEYWORDS = [
    "/bin/sh", "/bin/bash", "bash -i", "cmd.exe", "powershell", "/etc/passwd",
    "whoami", "ifconfig", "ipconfig", "netstat", "uname -", "cat /", "ls -",
    "rm -rf", "chmod ", "curl ", "wget ", "nc -", "ncat ", "/dev/tcp",
]
CMD_META_RE = re.compile(r"(\|\||&&|\$\(|`[^`]+`|;\s*\w+\s|\|\s*\w+)")
# ── 템플릿 / 역직렬화 / Log4Shell
TEMPLATE_RE = re.compile(r"(\$\{\s*(jndi|env|sys|lower|upper|date|::)\s*:?|\{\{\s*[\w.\[\]'\"]*\s*[*+\-/]|<%=|#\{\s*\w)",
                         re.IGNORECASE)
# ── NoSQL
NOSQL_KEYWORDS = ["$ne", "$gt", "$lt", "$where", "$regex", "$exists", "$in:"]
# ── 스캐너 / 봇 User-Agent
BOT_UA_RE = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zgrab|acunetix|nessus|burp|zaproxy|wpscan|dirbuster|gobuster|"
    r"hydra|metasploit|havij|curl/|wget/|python-requests|python-urllib|go-http-client|libwww|"
    r"java/|okhttp|scrapy|httpclient|postman|bot|crawler|spider|scanner)", re.IGNORECASE)

# 공격 도구 전용 UA(범용 curl/python 제외) — 정의상 공격 트래픽
SCANNER_UA_RE = re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|acunetix|nessus|burpsuite|"
                           r"zaproxy|wpscan|dirbuster|gobuster|hydra|metasploit|havij|"
                           r"commix|xsser|arachni|w3af)", re.IGNORECASE)
DIGIT_RE = re.compile(r"\d")
ALPHA_RE = re.compile(r"[^\W\d_]", re.UNICODE)
NONASCII_RE = re.compile(r"[^\x00-\x7F]")

def _alt(words):
    """키워드 목록을 하나의 정규식으로 합친다(긴 것 우선). str.count 반복보다 훨씬 빠르다."""
    return re.compile("|".join(re.escape(w) for w in sorted(words, key=len, reverse=True)),
                      re.IGNORECASE)

SQL_RE   = _alt(SQL_KEYWORDS)
XSS_RE   = _alt(XSS_KEYWORDS)
PT_RE    = _alt(PATH_TRAVERSAL_PATTERNS)
CMD_RE   = _alt(CMD_KEYWORDS)
NOSQL_RE = _alt(NOSQL_KEYWORDS)
REGEX_SCAN = 8_192   # 정규식·디코딩은 앞 8KB만 (공격 페이로드는 앞쪽에 위치)

# 모델 입력 피처 순서 (학습·서빙 공통. 이 순서가 바뀌면 모델이 조용히 틀립니다)
FEATURES = [
    "method_encoded", "file_extension_encoded",
    "url_len", "query_len", "body_len", "total_len",
    "path_depth", "param_count", "max_param_value_len",
    "special_char_count", "special_char_ratio",
    "digit_ratio", "alpha_ratio", "encoded_char_count", "non_ascii_count",
    "sql_keyword_count", "sql_tautology", "sql_comment_count",
    "xss_keyword_count", "xss_event_handler",
    "path_traversal_count", "cmd_keyword_count", "cmd_metachar",
    "template_injection", "nosql_count",
    "ua_is_bot", "ua_empty", "has_body",
]
CATEGORICAL = ["method", "file_extension"]


def _count(text, patterns):
    return sum(text.count(p) for p in patterns)


def build_feature_row(method, url_path, query_params, body_content, user_agent):
    """HTTP 요청 → 피처 dict. 학습 스크립트와 FastAPI 서버가 모두 이 함수를 사용한다."""
    method = (method or "UNKNOWN").upper()
    url_path = url_path or ""
    query_params = query_params or ""
    body_content = body_content or ""
    user_agent = user_agent or ""

    full_url = url_path + (("?" + query_params) if query_params else "")
    url_s, body_s, q_s = full_url[:MAX_SCAN], body_content[:MAX_SCAN], query_params[:MAX_SCAN]

    url_len, body_len = len(full_url), len(body_content)
    total_len = url_len + body_len

    decoded = unquote(url_s[:REGEX_SCAN]) + " " + unquote(body_s[:REGEX_SCAN])

    scan = url_s + body_s
    special = _count(url_s, SPECIAL_CHARS) + _count(body_s, SPECIAL_CHARS)
    n_nonascii = 0 if scan.isascii() else len(NONASCII_RE.findall(scan))

    params = []
    for blob in (q_s, body_s):
        for part in blob.split("&"):
            if "=" in part:
                params.append(part.split("=", 1)[1])
    seg = url_path.rsplit("/", 1)[-1]
    ext = seg.rsplit(".", 1)[-1].lower()[:12] if "." in seg else "NONE"

    return {
        "method": method,
        "file_extension": ext,
        "url_len": url_len,
        "query_len": len(query_params),
        "body_len": body_len,
        "total_len": total_len,
        "path_depth": len([p for p in url_path.split("/") if p]),
        "param_count": q_s.count("=") + body_s.count("="),
        "max_param_value_len": max((len(v) for v in params), default=0),
        "special_char_count": special,
        "special_char_ratio": special / total_len if total_len else 0.0,
        "digit_ratio": len(DIGIT_RE.findall(scan)) / total_len if total_len else 0.0,
        "alpha_ratio": len(ALPHA_RE.findall(scan)) / total_len if total_len else 0.0,
        "encoded_char_count": url_s.count("%") + body_s.count("%"),
        "non_ascii_count": n_nonascii,
        "sql_keyword_count": len(SQL_RE.findall(decoded)),
        "sql_tautology": 1 if SQL_TAUTOLOGY_RE.search(decoded) else 0,
        "sql_quote_comment": 1 if QUOTE_COMMENT_RE.search(decoded) else 0,
        "sql_union_select": 1 if UNION_SELECT_RE.search(decoded) else 0,
        "sql_comment_count": len(SQL_COMMENT_RE.findall(decoded)),
        "xss_keyword_count": len(XSS_RE.findall(decoded)),
        "xss_event_handler": 1 if XSS_EVENT_RE.search(decoded) else 0,
        "path_traversal_count": len(PT_RE.findall(decoded)),
        "cmd_keyword_count": len(CMD_RE.findall(decoded)),
        "cmd_metachar": 1 if CMD_META_RE.search(decoded) else 0,
        "template_injection": 1 if TEMPLATE_RE.search(decoded) else 0,
        "log4shell": 1 if LOG4SHELL_RE.search(decoded) else 0,
        "sql_statement": 1 if SQL_STMT_RE.search(decoded) else 0,
        "ssti": 1 if SSTI_RE.search(decoded) else 0,
        "nosql_count": len(NOSQL_RE.findall(decoded)),
        "ua_is_bot": 1 if BOT_UA_RE.search(user_agent) else 0,
        "ua_is_scanner": 1 if SCANNER_UA_RE.search(user_agent) else 0,
        "ua_empty": 1 if not user_agent.strip() else 0,
        "has_body": 1 if body_content else 0,
    }


def explain(row, probability, threshold):
    """모델이 공격으로 판정했을 때, 요청에서 실제로 발견된 근거를 문자열로 만든다.
    (SHAP 도입 전까지의 보조 설명. 점수 자체는 모델이 낸다)"""
    if probability < threshold:
        return "-"
    r = []
    if row["sql_tautology"]:        r.append("SQL 논리우회(OR/AND 토톨로지)")
    if row["sql_keyword_count"]:    r.append(f"SQL 키워드({row['sql_keyword_count']}개)")
    if row["sql_comment_count"]:    r.append("SQL 주석 패턴")
    if row["xss_keyword_count"]:    r.append(f"XSS 패턴({row['xss_keyword_count']}개)")
    if row["xss_event_handler"]:    r.append("XSS 이벤트 핸들러")
    if row["path_traversal_count"]: r.append("디렉터리 탈출 패턴")
    if row["cmd_keyword_count"] or row["cmd_metachar"]: r.append("커맨드 인젝션 패턴")
    if row["template_injection"]:   r.append("템플릿/JNDI 인젝션 패턴")
    if row["nosql_count"]:          r.append("NoSQL 연산자")
    if row["ua_is_bot"]:            r.append("스캐너/봇 User-Agent")
    if row["encoded_char_count"] > 8: r.append(f"과도한 URL 인코딩({row['encoded_char_count']}개)")
    if row["special_char_count"] > 8: r.append(f"특수문자 과다({row['special_char_count']}개)")
    if not r:
        r.append("통계적 이상 (키워드 불일치 — 신뢰도 낮음)")
    return ", ".join(r)


# ─────────────────────────────────────────────────────────────
# 규칙 게이트 — 학습 데이터에 거의 없어서 모델이 배우지 못하는 "정의상 공격"을
# 결정적으로 잡는다. 임계값 조정 대상이 아니며, 오탐률은 train 정상 트래픽에서
# 각 규칙별로 0.03~0.23%로 측정된 값만 채택했다.
# ─────────────────────────────────────────────────────────────
RULE_GATE = [
    ("sql_tautology",        lambda r: r["sql_tautology"] > 0,           "SQL 논리우회(OR/AND 토톨로지)"),
    ("xss_event_handler",    lambda r: r["xss_event_handler"] > 0,       "XSS 이벤트 핸들러"),
    ("xss_keyword_2",        lambda r: r["xss_keyword_count"] >= 2,      "XSS 태그/함수 다중 검출"),
    ("path_traversal_2",     lambda r: r["path_traversal_count"] >= 2,   "디렉터리 탈출 패턴"),
    ("nosql",                lambda r: r["nosql_count"] > 0,             "NoSQL 연산자 주입"),
    ("quote_comment",        lambda r: r["sql_quote_comment"] > 0,       "따옴표 뒤 주석/구문종결(SQLi)"),
    ("union_select",         lambda r: r["sql_union_select"] > 0,        "UNION SELECT 구문"),
    ("cmd_with_meta",        lambda r: r["cmd_keyword_count"] >= 1 and r["cmd_metachar"] > 0,
                                                                          "쉘 메타문자 + 시스템 명령"),
    ("cmd_keyword_2",        lambda r: r["cmd_keyword_count"] >= 2,      "커맨드 인젝션 패턴"),
    ("log4shell",            lambda r: r["log4shell"] > 0,               "JNDI/Log4Shell 인젝션"),
    ("sql_statement",        lambda r: r["sql_statement"] > 0,           "SQL 조작 구문(DROP/DELETE/INSERT 등)"),
    ("ssti",                 lambda r: r["ssti"] > 0,                    "서버사이드 템플릿 인젝션"),
    ("scanner_ua",           lambda r: r["ua_is_scanner"] > 0,           "공격 도구 User-Agent"),
]

def rule_hits(row):
    return [(name, desc) for name, fn, desc in RULE_GATE if fn(row)]

# 응답 상태 코드 정책 — 학습 데이터에 status가 없어 모델 피처로는 쓸 수 없다.
# 대신 판정 후 위험도 조정에만 사용한다.
STATUS_DOWNGRADE = {101, 304}          # 프로토콜 전환 / 캐시 검증 — 콘텐츠 반환 없음
STATUS_UPSTREAM_FAIL = {502, 503, 504} # 백엔드 미도달 — 공격 성공 불가, 차단 유보
STATUS_PROBE = {400, 401, 403, 404, 405, 500}  # 탐색 신호 — 위험도 상향

def adjust_by_status(verdict, confidence, status):
    """(verdict, confidence) → 상태 코드 반영 결과. verdict: 'attack'|'normal'"""
    if status is None:
        return verdict, confidence, None
    if verdict == "attack" and status in STATUS_DOWNGRADE:
        return "normal", "LOW", f"status {status}: 콘텐츠 미반환 흐름이라 위협에서 제외"
    if verdict == "attack" and status in STATUS_UPSTREAM_FAIL:
        return "attack", "LOW", f"status {status}: 백엔드 미도달 — 차단 유보, 행동 분석 대상"
    if verdict == "attack" and status in STATUS_PROBE:
        return "attack", "HIGH", f"status {status}: 실패/오류 응답 — 탐색 정황"
    return verdict, confidence, None
