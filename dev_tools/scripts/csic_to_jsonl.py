import json
import re
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime

# 0. cisc_id를 기반으로 가짜 IP 생성 (테스트용)
def make_synthetic_ip(request_id: str) -> str:
    n = int(request_id)
    return f"10.0.{(n // 250) % 10}.{n%250 +1}"

# 1. 경로 설정 
PROJECT_ROOT = Path(__file__).resolve().parents[2]      # 프로젝트 루트 위치
INPUT_DIR = PROJECT_ROOT / "dev_tools" / "logs"         # 원본 로그 위치
OUTPUT_DIR = PROJECT_ROOT / "dev_tools" / "parsed_logs" # 변환 결과 저장 위치

# 2. 특수 문자 개수 세는 부분
SPECIAL_CHARS = ["'" , '"',"<",">","--",";","%"]

def count_special_chars(text: str) -> int:
    return sum(text.count(char) for char in SPECIAL_CHARS)

# 3. 요청 블록 분리
def split_blocks(text: str) -> list[list[str]]:
    blocks = []
    current = []
    in_block = False
    
    for line in text.splitlines():
        if line.startswith("Start - Id:"):
            in_block = True
            current = [line]
            continue

        if in_block:
            current.append(line)

            if line.startswith("End - Id:"):
                blocks.append(current)
                current = []
                in_block = False
    return blocks


# 4. 요청 하나 파싱하는 부분 
def parse_block(block: list[str]) -> dict | None:
    request_id = None
    label = None
    method = None
    raw_url = None
    user_agent = ""
    body_lines = []

    # 1) id, class, request line 찾기
    request_line_index = -1

    for i ,line in enumerate(block):
        # ID 추출
        if line.startswith("Start - Id:"):
            request_id = line.replace("Start - Id:","").strip()

        # class 추출
        elif line.startswith("class:"):
            label = line.replace("class:","").strip()

        # GET/POST/etc 요청 줄 찾기
        elif re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+",line):
            parts = line.split()
            if len(parts) >= 3:
                method = parts[0]
                raw_url = parts[1]
                request_line_index = i

    if method is None or raw_url is None:
        return None
    
    # 2) header/body 분리
    header_started = request_line_index + 1
    headers = {}

    for line in block[header_started:]:
        stripped = line.strip()

        # End - Id: 를 만나면 요청 하나가 끝났다는 뜻이니까 반복문 종료
        if stripped.startswith("End - Id:"):
            break
        # 빈 줄
        if stripped == "":
            continue

        # Header 형식인지 검사
        if re.match(r"^[A-Za-z0-9-]+:\s*", stripped):
            key, value = stripped.split(":",1)
            headers[key.lower()] = value.strip()
        else: 
            body_lines.append(stripped)

        
    user_agent = headers.get("user-agent","")

    body_content = "\n".join(body_lines).strip()

    # body 부분이 null일 경우 빈 문자열로 처리
    if body_content.lower() == "null":
        body_content = ""


    # 3) URL 파싱
    parsed_url = urlparse(raw_url)
    url_path = parsed_url.path
    query_params = parsed_url.query

    full_url = url_path + (f"?{query_params}" if query_params else "")
    url_len = len(full_url)
    special_char_count = count_special_chars(full_url + body_content)

    # 4) AI/ Spring 입력 JSON 형태로 변환
    return {
        "source" : "cisc2010",
        "csic_id" : request_id,
        "class" : label,
        "method" : method,
        "url_path": url_path,
        "query_params" : query_params,
        "body_content": body_content,
        "user_agent" : user_agent,
        "url_len":url_len,
        "special_char_count": special_char_count,
        "ip_address" : make_synthetic_ip(request_id),
        "timestamp" : datetime.now().isoformat(timespec="seconds")
    }

        
def convert_file(input_path: Path, output_path:Path) -> int:
    text = input_path.read_text(encoding = "utf-8",errors="ignore")
    blocks = split_blocks(text)

    count = 0

    with output_path.open("w",encoding="utf-8") as f:
        for block in blocks:
            parsed = parse_block(block)

            if parsed is None:
                continue

            f.write(json.dumps(parsed,ensure_ascii= False) + "\n")
            count +=1

    return count


def main():
    OUTPUT_DIR.mkdir(parents=True,exist_ok=True)

    input_files = [
        file for file in INPUT_DIR.iterdir()
        if file.is_file() and not file.name.endswith(".jsonl")
    ]

    if not input_files:
        print(f"[WARN] 입력 파일이 없습니다: {INPUT_DIR}")
        return
    
    for input_file in input_files:
        output_file = OUTPUT_DIR / f"{input_file.stem}.jsonl"
        count = convert_file(input_file,output_file)

        print(f"[OK] {input_file.name} -> {output_file.name} | {count}개 변환")

if __name__ == '__main__':
    main()