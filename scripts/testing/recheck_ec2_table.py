"""P7 기존 기록의 대표 위협 행만 재조회한다. 새 probe·차단 변경·DB 쓰기는 하지 않는다."""
import argparse
import asyncio
from datetime import datetime
import hashlib
import json
import re
from urllib.parse import parse_qs, urlsplit

from ec2_connection import observe_threat_row
from e2e_environment import select_environment
from run_ec2_collection import local_git_state
from run_experiment import ROOT, HERE, KST, now, reserve, save, format_record_time


def target_from_source(run_id):
    if not re.fullmatch(r'[0-9]{8}T[0-9]{6}\+0900-ec2-connection-r[0-9]{2}',run_id):
        raise ValueError('SOURCE_RUN_ID_INVALID')
    directory=ROOT/'build/test-runs'/run_id
    source=json.loads((directory/'pipeline-01.json').read_text(encoding='utf-8'))
    rows=[r for r in source['database'] if r['kind']=='probe']
    if len(rows)!=1 or rows[0]['aiRows']!=1 or rows[0]['wafRows']!=1:
        raise ValueError('SOURCE_PROBE_NOT_VERIFIED')
    row=rows[0]
    trace=source['traces']
    def threat(stage):
        ids={t['threatId'] for t in trace if t['stage']==stage and t['requestId']==row['requestId'] and t.get('threatId')}
        if len(ids)!=1: raise ValueError('SOURCE_THREAT_NOT_VERIFIED')
        return ids.pop()
    waf,ai=threat('WAF_COMMITTED'),threat('AI_RESULT_COMMITTED')
    return dict(id=min(waf,ai),logId=row['logId'],wafThreatId=waf,aiThreatId=ai,
        requestId=row['requestId'],threatTypes=['WAF Detection','AI Detection'])


def safe_group(value):
    if not isinstance(value,dict) or not isinstance(value.get('content'),list):
        raise ValueError('GROUP_RESPONSE_INVALID')
    keys=('id','logId','wafThreatId','aiThreatId','threatTypes')
    return [dict((k,row.get(k)) for k in keys) for row in value['content']]


def matching_group_response(response,threat_id):
    parsed=urlsplit(response.url)
    return (parsed.path=='/api/v1/threats/grouped' and response.request.method=='GET'
        and parse_qs(parsed.query).get('threatId')==[str(threat_id)])


async def observe(manifest,output,target):
    from playwright.async_api import async_playwright
    env=select_environment('ec2')
    origin=urlsplit(env.dashboard_url)
    async with async_playwright() as pw:
        browser=await pw.chromium.launch(channel='chrome',headless=False)
        manifest['browser_version']=browser.version
        try:
            context=await browser.new_context(viewport=dict(width=1440,height=1000))
            async def restrict(route):
                request=route.request
                url=urlsplit(request.url)
                same_origin=(url.scheme,url.hostname,url.port)==(origin.scheme,origin.hostname,origin.port)
                allowed=request.method in ('GET','HEAD') or (request.method=='POST' and url.path=='/api/v1/auth/login')
                if not same_origin or not allowed:
                    await route.abort()
                else:
                    await route.continue_()
            await context.route('**/*',restrict)
            await context.expose_binding('__dgBinding',lambda source,event: None)
            await context.add_init_script(path=str(HERE/'browser_trace.js'))
            page=await context.new_page()
            await page.goto(env.dashboard_url,timeout=30000)
            print('P7_TABLE_LOGIN_REQUIRED: 열린 EC2 관리자 Chrome에 직접 로그인해주세요. 기존 위협 행만 조회합니다.',flush=True)
            await page.wait_for_function('window.__dgReady === true',timeout=600000)
            manifest['manual_login_stomp']=True
            async with page.expect_response(lambda r:matching_group_response(r,target['id']),timeout=20000) as pending:
                await observe_threat_row(page,target['id'],target['logId'])
            response=await pending.value
            if response.status!=200: raise RuntimeError('GROUP_API_NOT_200')
            rows=safe_group(await response.json())
            if rows!=[{k:target[k] for k in ('id','logId','wafThreatId','aiThreatId','threatTypes')}]:
                raise RuntimeError('GROUP_ID_OR_SOURCES_MISMATCH')
            panel=page.locator('section[aria-label="위협 탐지 목록"]')
            table=panel.get_by_role('region',name='위협 탐지 데이터 표',exact=True)
            row=table.locator('tbody tr')
            checks=dict(group_api_200=True,group_ids_and_sources_match=True,
                representative_table=True,one_grouped_row=await row.count()==1,
                displayed_first_threat_id=(await row.first.locator('td').first.inner_text()).strip()==f"#{target['id']}",
                linked_log_button=await table.get_by_role('button',name=f"원본 로그 {target['logId']} 상세 보기",exact=True).count()==1,
                waf_detail_button=await table.get_by_role('button',name=f"위협 {target['wafThreatId']} WAF 상세 보기",exact=True).count()==1)
            save(output/'table-observation.json',dict(at=now(),target=target,group_response=rows,checks=checks))
            manifest['checks']=checks
            if not all(checks.values()): raise RuntimeError('TABLE_DOM_NOT_CONFIRMED')
        finally:
            await browser.close()


def report(m):
    lines=[f"# 실험 기록: {format_record_time(m['planned_at']).split()[0]} — P7 대표 위협 행 재확인",'',
        '[EC2 목차](../README.md) · [P7](../P7.md)','', '## 실행 정보',f"- ID: `{m['id']}`",
        f"- 원본 회차: `{m['source_run']}`",f"- 판정: {m['verdict']}",'- 성능 판정: NOT_EVALUATED',
        f"- 시작 / 종료: {format_record_time(m.get('started_at'))} / {format_record_time(m.get('ended_at'))}",
        '## S — Situation','- 앞선 P7 핵심 연결·원복 확인 후 대표 행 관측만 남았다.',
        '## T — Task·Target','- 기존 위협의 실제 검색 응답·ID 연결·위협 표 내부 DOM을 확인한다.',
        '- 새 JuiceShop 요청·probe·부하·차단 변경·등록 삭제 없이 관리자 조회만 수행한다.',
        '## A — Action','- 새 관리자 Chrome에 사용자가 직접 로그인. 세션·비밀번호·쿠키는 저장하지 않는다.',
        '- 위협 번호로 검색하고 로그·WAF·AI ID와 단일 그룹 행을 대조한다.',
        '## R — Result']
    lines += [f'- {k}: {v}' for k,v in m.get('checks',{}).items()]
    lines += ['## T — Trouble',*['- '+e for e in m.get('errors',[])],
        '- 원본 r03의 INCONCLUSIVE 판정·파일은 변경하지 않는다. 이번 증거로 남은 항목을 종결한다.']
    return '\n'.join(lines)+'\n'


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-run',required=True)
    p.add_argument('--round',type=int,default=1)
    p.add_argument('--execute',action='store_true')
    a=p.parse_args(argv)
    if not 1<=a.round<=99: p.error('회차는 1~99입니다.')
    target=target_from_source(a.source_run)
    if not a.execute:
        print(json.dumps(dict(mode='PLAN_ONLY',target=target,new_probe_requests=0,configuration_changes=False),ensure_ascii=False,indent=2))
        return 0
    rid=datetime.now(KST).strftime('%Y%m%dT%H%M%S%z')+f'-ec2-table-recheck-r{a.round:02d}'
    output,path=reserve(ROOT,rid,'ec2')
    m=dict(id=rid,source_run=a.source_run,planned_at=now(),started_at=now(),verdict='INCONCLUSIVE',
        performance_verdict='NOT_EVALUATED',new_probe_requests=0,configuration_changes=False,checks={},errors=[],**local_git_state())
    m['source_sha256']={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in
        ('recheck_ec2_table.py','ec2_connection.py','browser_trace.js')}
    save(output/'manifest.json',m)
    path.write_text(report(m),encoding='utf-8')
    try:
        asyncio.run(observe(m,output,target))
        m['verdict']='PASS'
    except KeyboardInterrupt:
        m['errors'].append('USER_INTERRUPTED')
    except Exception as error:
        m['errors'].append(str(error) if type(error) is RuntimeError else type(error).__name__)
    finally:
        m['ended_at']=now()
        save(output/'manifest.json',m)
        path.write_text(report(m),encoding='utf-8')
    print('재확인: '+m['verdict'])
    print('보고서: '+str(path))
    return 0 if m['verdict']=='PASS' else 1


if __name__=='__main__':
    raise SystemExit(main())
