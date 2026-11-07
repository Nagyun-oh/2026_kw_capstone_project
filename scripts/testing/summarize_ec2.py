"""동일 조건의 EC2 정식 3회 결과만 합산한다. 원본을 수정하지 않는다."""
import argparse
import hashlib
import json
from pathlib import Path

from ec2_load_policy import summarize_stage
from run_experiment import ROOT,now,format_record_time


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runs',nargs=3,required=True,type=Path)
    p.add_argument('--output',required=True,type=Path)
    a=p.parse_args(argv)
    output=a.output.resolve()
    if (not output.is_relative_to((ROOT/'docs/testing/ec2').resolve()) or output.suffix!='.md'
            or output.exists() or output.with_suffix('.json').exists()):
        p.error('EC2 문서 디렉터리의 새 Markdown 경로를 사용해주세요.')
    rows=[]
    hashes={}
    for run in a.runs:
        run=run.resolve()
        if not run.is_relative_to((ROOT/'build/test-runs').resolve()): p.error('기존 실험 원본 디렉터리만 지원합니다.')
        m=json.loads((run/'manifest.json').read_text(encoding='utf-8'))
        r=json.loads((run/'metrics.json').read_text(encoding='utf-8'))
        rows.append((m,r))
        hashes[m['id']]=hashlib.sha256((run/'metrics.json').read_bytes()).hexdigest()
    result=dict(at=now(),**summarize_stage(rows),metrics_sha256=hashes)
    output.parent.mkdir(parents=True,exist_ok=True)
    text=f"# {format_record_time(result['at']).split()[0]} — EC2 동일 단계 3회 집계\n\n판정: **{result['verdict']}**\n\n"
    text+='\n'.join('- '+m['id']+': '+r['verdict'] for m,r in rows)
    text+='\n\n원본 지연 표본 합산·조건·해시는 같은 이름의 JSON을 참고한다. p99 평균을 사용하지 않는다.\n'
    with output.open('x',encoding='utf-8') as f: f.write(text)
    with output.with_suffix('.json').open('x',encoding='utf-8') as f: json.dump(result,f,ensure_ascii=False,indent=2)
    return 0


if __name__=='__main__': raise SystemExit(main())
