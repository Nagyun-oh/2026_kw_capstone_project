"""DVWA를 정상 사용자처럼 조작하고, 그때 발생한 HTTP 요청을 샘플 JSONL로 기록한다. (T2 오탐 측정)

목적: JuiceShop과 다른 스택(PHP·폼 전송·쿠키 세션)인 DVWA에서 "그 사이트의 정상 동작"이
WAF·AI에 오탐으로 걸리는지 보려는 것. 그래서 모든 요청은 정상 값만 쓴다
(예: 명령 삽입 페이지의 ping 입력에 127.0.0.1, SQL 조회에 id=1). 공격 문자열은 보내지 않는다.

동작
- 실제 DVWA(기본 127.0.0.1:4280)에 접속해 DB 초기화 → 로그인 → 보안 레벨 설정 → 각 기능을 정상 값으로
  사용 → 로그아웃까지 실제로 수행한다. 각 단계의 응답 코드(200/302)를 확인해 "정상 동작이 깨지지 않는지"도 본다.
- 브라우저처럼 페이지를 받으면 그 페이지가 참조하는 같은 출처 정적 자원(css·js·이미지·favicon)도 한 번씩 받는다.
- 보낸 요청을 run_pipeline_test.py가 읽는 샘플 형식(label_binary=0, source=dvwa)으로 기록한다.
  이 파일을 실험실(wafs/) ModSecurity·Coraza와 AI에 재생해 오탐을 비교한다.

제외: 파일 업로드(multipart)는 바이너리 본문이라 JSONL 재생 시 바이트가 깨질 수 있어 기록에서 뺀다.
      대신 정상 업로드가 동작하는지는 실제로 확인하고 건수를 출력한다.

사용 예:
    docker compose -f targets/dvwa/docker-compose.yml up -d
    python3 dev_tools/scripts/capture_dvwa_traffic.py \\
        --base http://127.0.0.1:4280 --security low \\
        --out dev_tools/datasets/t2-dvwa/dvwa-normal.jsonl
"""
import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlsplit, parse_qsl

try:
    import requests
except ImportError:
    sys.exit("requests가 필요합니다: pip install requests")

# 실제 크롬(Windows)이 보내는 헤더에 맞춘다. CRS는 User-Agent·Accept 누락 등을 룰로 보기 때문에
# 헤더가 브라우저처럼 보여야 정상 트래픽의 오탐을 제대로 측정할 수 있다.
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36")
BASE_HEADERS = {
    "User-Agent": UA,
    "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate",
    "sec-ch-ua": '"Chromium";v="129", "Not=A?Brand";v="8", "Google Chrome";v="129"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "Upgrade-Insecure-Requests": "1",
}
DOC_ACCEPT = ("text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
ASSET_ACCEPT = {
    "css": "text/css,*/*;q=0.1",
    "js": "*/*",
    "img": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
    "ico": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
}
ASSET_RE = re.compile(r'(?:href|src)\s*=\s*["\']([^"\']+)["\']', re.I)
TOKEN_RE = re.compile(r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-f]+)['\"]", re.I)


class Capture:
    """DVWA를 조작하면서 보낸 요청을 샘플 형식으로 모은다."""

    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.origin = urlsplit(self.base)
        self.sess = requests.Session()
        self.sess.headers.update(BASE_HEADERS)
        self.records = []
        self.seen_assets = set()
        self.n = 0
        self.warnings = []

    def _same_origin(self, url: str) -> bool:
        parts = urlsplit(url)
        return (not parts.netloc) or (parts.netloc == self.origin.netloc)

    def _record(self, method: str, url: str, note: str, body: str, content_type: str, referer: str, dest: str):
        """보낸 요청 하나를 run_pipeline_test.py 샘플 형식으로 남긴다(정상=label 0)."""
        parts = urlsplit(url)
        accept = DOC_ACCEPT if dest == "document" else ASSET_ACCEPT.get(dest, "*/*")
        headers = [["host", self.origin.netloc], ["user-agent", UA], ["accept", accept],
                   ["accept-language", BASE_HEADERS["Accept-Language"]],
                   ["sec-ch-ua", BASE_HEADERS["sec-ch-ua"]], ["sec-ch-ua-mobile", "?0"],
                   ["sec-ch-ua-platform", '"Windows"']]
        if dest == "document":
            headers += [["upgrade-insecure-requests", "1"], ["sec-fetch-site", "same-origin" if referer else "none"],
                        ["sec-fetch-mode", "navigate"], ["sec-fetch-user", "?1"], ["sec-fetch-dest", "document"]]
        else:
            headers += [["sec-fetch-site", "same-origin"], ["sec-fetch-mode", "no-cors"],
                        ["sec-fetch-dest", {"css": "style", "js": "script", "img": "image", "ico": "image"}.get(dest, "empty")]]
        if referer:
            headers.append(["referer", referer])
        if content_type:
            headers.append(["content-type", content_type])
        cookie = "; ".join(f"{c.name}={c.value}" for c in self.sess.cookies)
        if cookie:
            headers.append(["cookie", cookie])
        self.n += 1
        self.records.append({
            "sample_id": f"d{self.n:05d}", "source": "dvwa", "record_id": note,
            "label_binary": 0, "label_families": [],
            "method": method, "path": parts.path or "/", "query": parts.query,
            "headers": headers, "body": body, "content_type": content_type,
        })

    def get(self, path: str, note: str, referer: str = "", load_assets: bool = True):
        url = urljoin(self.base + "/", path.lstrip("/"))
        ref = urljoin(self.base + "/", referer.lstrip("/")) if referer else ""
        self._record("GET", url, note, "", "", ref, "document")
        resp = self.sess.get(url, allow_redirects=False)
        self._check(resp, note)
        if load_assets and "text/html" in resp.headers.get("content-type", ""):
            self._load_assets(resp.text, url)
        return resp

    def post(self, path: str, data: dict, note: str, referer: str = ""):
        url = urljoin(self.base + "/", path.lstrip("/"))
        ref = urljoin(self.base + "/", referer.lstrip("/")) if referer else ""
        body = "&".join(f"{k}={requests.utils.quote(str(v), safe='')}" for k, v in data.items())
        self._record("POST", url, note, body, "application/x-www-form-urlencoded", ref, "document")
        resp = self.sess.post(url, data=data, allow_redirects=False)
        self._check(resp, note)
        return resp

    def _load_assets(self, html: str, page_url: str):
        for raw in ASSET_RE.findall(html):
            if raw.startswith(("data:", "javascript:", "#", "mailto:")):
                continue
            if not self._same_origin(raw):
                continue
            asset = urljoin(page_url, raw)
            path = urlsplit(asset).path
            ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
            dest = {"css": "css", "js": "js", "png": "img", "jpg": "img", "jpeg": "img",
                    "gif": "img", "svg": "img", "ico": "ico"}.get(ext)
            if not dest or asset in self.seen_assets:
                continue
            self.seen_assets.add(asset)
            self._record("GET", asset, f"asset:{path}", "", "", page_url, dest)
            try:
                r = self.sess.get(asset, allow_redirects=False)
                self._check(r, f"asset:{path}", quiet=True)
            except requests.RequestException as exc:
                self.warnings.append(f"asset {path}: {exc}")

    def token(self, resp) -> str:
        m = TOKEN_RE.search(resp.text)
        return m.group(1) if m else ""

    def _check(self, resp, note: str, quiet: bool = False):
        if resp.status_code >= 400:
            self.warnings.append(f"{note}: HTTP {resp.status_code}")
        if not quiet:
            print(f"  [{resp.status_code}] {note}", flush=True)


def run(cap: Capture, security: str):
    """정상 사용자 시나리오. 모든 입력은 각 기능의 정상 값이다(공격 문자열 없음)."""
    # 1) 최초 설치: DB 생성/초기화 (처음 쓰는 사이트의 정상 셋업)
    r = cap.get("setup.php", "셋업 페이지 열기")
    cap.post("setup.php", {"create_db": "Create / Reset Database", "user_token": cap.token(r)},
             "DB 생성/초기화", referer="setup.php")

    # 2) 로그인 (기본 계정)
    r = cap.get("login.php", "로그인 페이지 열기")
    cap.post("login.php", {"username": "admin", "password": "password", "Login": "Login",
                           "user_token": cap.token(r)}, "로그인", referer="login.php")

    # 3) 홈 + 보안 레벨 설정 (운영자의 정상 설정 동작)
    cap.get("index.php", "홈 화면", referer="login.php")
    r = cap.get("security.php", "보안 설정 페이지", referer="index.php")
    cap.post("security.php", {"security": security, "seclev_submit": "Submit", "user_token": cap.token(r)},
             f"보안 레벨 {security}로 변경", referer="security.php")

    # 4) 안내 페이지들 열람
    cap.get("instructions.php", "사용 안내", referer="index.php")
    cap.get("about.php", "소개 페이지", referer="index.php")

    # 5) 각 기능을 정상 값으로 사용
    cap.get("vulnerabilities/sqli/", "SQL 조회 페이지", referer="index.php")
    cap.get("vulnerabilities/sqli/?id=1&Submit=Submit", "사용자 ID 1 조회(정상)", referer="vulnerabilities/sqli/")
    cap.get("vulnerabilities/sqli/?id=2&Submit=Submit", "사용자 ID 2 조회(정상)", referer="vulnerabilities/sqli/")

    cap.get("vulnerabilities/sqli_blind/", "블라인드 SQL 페이지", referer="index.php")
    cap.get("vulnerabilities/sqli_blind/?id=1&Submit=Submit", "블라인드 ID 1 조회(정상)",
            referer="vulnerabilities/sqli_blind/")

    cap.get("vulnerabilities/xss_r/", "반사형 XSS 페이지", referer="index.php")
    cap.get("vulnerabilities/xss_r/?name=Alice", "이름 Alice 입력(정상)", referer="vulnerabilities/xss_r/")
    cap.get("vulnerabilities/xss_r/?name=%ED%99%8D%EA%B8%B8%EB%8F%99", "이름 홍길동 입력(정상)",
            referer="vulnerabilities/xss_r/")
    # 아래 입력들은 정상 텍스트지만 아포스트로피·앰퍼샌드·따옴표를 포함한다(시그니처 WAF의 흔한 오탐 지점).
    cap.get("vulnerabilities/xss_r/?name=O%27Brien", "이름 O'Brien(아포스트로피, 정상)",
            referer="vulnerabilities/xss_r/")
    cap.get("vulnerabilities/xss_r/?name=Tom%20%26%20Jerry", "이름 Tom & Jerry(앰퍼샌드, 정상)",
            referer="vulnerabilities/xss_r/")

    r = cap.get("vulnerabilities/xss_s/", "저장형 XSS(방명록) 페이지", referer="index.php")
    cap.post("vulnerabilities/xss_s/", {"txtName": "Alice", "mtxMessage": "Nice lab, thanks for sharing!",
             "btnSign": "Sign Guestbook"}, "방명록 정상 작성", referer="vulnerabilities/xss_s/")
    cap.post("vulnerabilities/xss_s/", {"txtName": "O'Brien", "mtxMessage": "It's great & very useful; thanks!!",
             "btnSign": "Sign Guestbook"}, "방명록 작성(아포스트로피·앰퍼샌드, 정상)", referer="vulnerabilities/xss_s/")
    cap.post("vulnerabilities/xss_s/", {"txtName": "François", "mtxMessage": "Prix: 10€ -- très bien (2>1).",
             "btnSign": "Sign Guestbook"}, "방명록 작성(악센트·수식 기호, 정상)", referer="vulnerabilities/xss_s/")

    cap.get("vulnerabilities/exec/", "명령 실행(ping) 페이지", referer="index.php")
    cap.post("vulnerabilities/exec/", {"ip": "127.0.0.1", "Submit": "Submit"},
             "로컬호스트 ping(정상)", referer="vulnerabilities/exec/")
    cap.post("vulnerabilities/exec/", {"ip": "8.8.8.8", "Submit": "Submit"},
             "공개 DNS ping(정상)", referer="vulnerabilities/exec/")
    cap.post("vulnerabilities/exec/", {"ip": "google.com", "Submit": "Submit"},
             "호스트명 ping(정상)", referer="vulnerabilities/exec/")

    cap.get("vulnerabilities/brute/", "무차별 로그인 페이지", referer="index.php")
    cap.get("vulnerabilities/brute/?username=admin&password=password&Login=Login",
            "정상 로그인 시도", referer="vulnerabilities/brute/")

    cap.get("vulnerabilities/fi/?page=include.php", "파일 포함 기본 페이지(정상)", referer="index.php")
    cap.get("vulnerabilities/fi/?page=file1.php", "파일 포함 file1(정상)", referer="vulnerabilities/fi/?page=include.php")

    r = cap.get("vulnerabilities/csrf/", "비밀번호 변경 페이지", referer="index.php")
    cap.get("vulnerabilities/csrf/?password_new=Passw0rd%21&password_conf=Passw0rd%21&Change=Change&user_token="
            + cap.token(r), "본인 비밀번호 변경(정상)", referer="vulnerabilities/csrf/")

    cap.get("vulnerabilities/weak_id/", "약한 세션ID 페이지 열람", referer="index.php")
    cap.get("vulnerabilities/csp/", "CSP 페이지 열람", referer="index.php")
    cap.get("vulnerabilities/javascript/", "자바스크립트 페이지 열람", referer="index.php")
    cap.get("vulnerabilities/open_redirect/", "오픈 리다이렉트 페이지 열람", referer="index.php")

    cap.get("favicon.ico", "favicon", referer="index.php", load_assets=False)

    # 6) 파일 업로드: 정상 이미지가 올라가는지 기능만 확인(바이너리 본문이라 재생 세트에는 넣지 않음)
    upload_ok = functional_upload(cap)

    # 7) 로그아웃
    cap.get("logout.php", "로그아웃", referer="index.php")
    return upload_ok


def functional_upload(cap: Capture) -> str:
    """정상 PNG 업로드가 동작하는지만 확인한다(기록에는 넣지 않음)."""
    png = bytes.fromhex("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
                        "890000000a49444154789c6360000002000154a24f5f0000000049454e44ae426082")
    url = urljoin(cap.base + "/", "vulnerabilities/upload/")
    try:
        cap.sess.get(url)
        r = cap.sess.post(url, files={"uploaded": ("avatar.png", png, "image/png")},
                          data={"Upload": "Upload"}, allow_redirects=False)
        ok = "succesfully uploaded" in r.text.lower() or r.status_code in (200, 302)
        print(f"  [{r.status_code}] 정상 이미지 업로드 기능 확인 ({'성공' if ok else '실패'})", flush=True)
        return "성공" if ok else f"응답 {r.status_code}"
    except requests.RequestException as exc:
        return f"오류 {exc}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:4280")
    ap.add_argument("--security", default="low", choices=["low", "medium", "high", "impossible"],
                    help="DVWA 보안 레벨(정상 운영 설정). 요청 모양에 큰 영향은 없다")
    ap.add_argument("--out", type=Path, default=Path("dev_tools/datasets/t2-dvwa/dvwa-normal.jsonl"))
    args = ap.parse_args()

    cap = Capture(args.base)
    print(f"DVWA 정상 트래픽 수집 시작: {args.base} (security={args.security})", flush=True)
    upload_ok = run(cap, args.security)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for rec in cap.records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"\n기록된 정상 요청: {len(cap.records)}건 → {args.out}")
    print(f"  (정적 자원 {len(cap.seen_assets)}건 포함, 파일 업로드 기능: {upload_ok} — 재생 세트 제외)")
    if cap.warnings:
        print(f"경고 {len(cap.warnings)}건:")
        for w in cap.warnings[:20]:
            print(f"  - {w}")


if __name__ == "__main__":
    main()
