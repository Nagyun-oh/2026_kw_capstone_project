"""P6 DB 스냅샷·누적 계수 차이. 미확인·초기화를 0으로 대체하지 않는다."""
import json
import math
import re
import subprocess
import time

from ec2_db_queries import FIELDS,TABLES,STATUS_NAMES,GAUGES,DIGEST_COUNTERS,queries
from e2e_remote import HERE,now


def number(value,nullable=False):
    return (value is None and nullable) or (type(value) in (int,float) and math.isfinite(value) and value>=0)


def parse_db_observation(value,run_id=None):
    if (not isinstance(value,dict) or value.get('schema')!='dualguard-ec2-db-v1'
            or value.get('run_id')!=run_id or value.get('load_generated') is not False):
        raise ValueError('DB 관측 응답 형식 오류')
    errors=[]
    sections={}
    for name,fields in FIELDS.items():
        section=value.get('sections',{}).get(name,{})
        rows=section.get('rows')
        if section.get('status')!='OK' or not isinstance(rows,list):
            codes=[{k:r.get(k) for k in ('authentication','code','sqlstate')} for r in section.get('error_codes',[])]
            sections[name]=dict(status='UNAVAILABLE',rows=None,authentication=None,error_codes=codes)
            errors.append(name+'_unavailable')
            continue
        if any(not isinstance(r,dict) or set(r)-set(fields) for r in rows):
            raise ValueError('허용하지 않는 DB 관측 필드')
        if name in ('metadata','instrumentation','locks','transactions') and len(rows)!=1:
            raise ValueError('단일 DB 관측 결과가 누락됐습니다.')
        if name=='metadata' and (not isinstance(rows[0].get('server_hash'),str)
                or not re.fullmatch(r'[A-Fa-f0-9]{64}',rows[0]['server_hash'])):
            raise ValueError('DB 서버 식별 근거 오류')
        if name=='digests':
            if len(rows)>2000: errors.append('digests_truncated')
            seen=set()
            for row in rows:
                digest=row.get('digest')
                if digest is None:
                    errors.append('digest_overflow_bucket')
                elif not isinstance(digest,str) or not re.fullmatch(r'[A-Fa-f0-9]{64}',digest) or digest in seen:
                    raise ValueError('digest 식별값 오류')
                seen.add(digest)
                if any(not number(row.get(k)) for k in DIGEST_COUNTERS): raise ValueError('digest 계수 오류')
                if row.get('verb') not in ('SELECT','INSERT','UPDATE','DELETE','OTHER'): raise ValueError('SQL 종류 오류')
                if not isinstance(row.get('tables'),list) or set(row['tables'])-set(TABLES)-{None}: raise ValueError('테이블 표식 오류')
        if name=='tables' and {r.get('table') for r in rows}!=set(TABLES): errors.append('tables_incomplete')
        if name=='outbox':
            if any(r.get('state') not in ('PENDING','IN_FLIGHT','SENT') or not number(r.get('count')) for r in rows):
                raise ValueError('outbox 관측 오류')
        if name=='status':
            canonical={s.lower():s for s in STATUS_NAMES}
            for row in rows:
                key=str(row.get('name')).lower()
                if key not in canonical or not str(row.get('value','')).isdigit(): raise ValueError('전역 상태 계수 오류')
                row['name']=canonical[key]
                row['value']=int(row['value'])
            if 'Uptime' not in {r['name'] for r in rows}: errors.append('uptime_unavailable')
        sections[name]=dict(status='OK',rows=rows,authentication=section.get('authentication'),
            error_codes=[{k:r.get(k) for k in ('authentication','code','sqlstate')} for r in section.get('error_codes',[])])
    instrumentation=sections['instrumentation']['rows']
    if instrumentation:
        point=instrumentation[0]
        if (point.get('digest_consumer')!='YES' or point.get('statement_consumer')!='YES'
                or not number(point.get('timed_statement_instruments')) or point['timed_statement_instruments']==0):
            errors.append('statement_instrumentation_not_ready')
    metadata=sections['metadata']['rows']
    if metadata and metadata[0].get('performance_schema')!=1: errors.append('performance_schema_disabled')
    commands=[{k:c.get(k) for k in ('check','started_at','ended_at','status','exit_code','elapsed_ms','bytes_read','lines_read')}
              for c in value.get('commands',[])]
    if not commands: errors.append('command_evidence_missing')
    sha=value.get('app_sha')
    if not isinstance(sha,str) or not re.fullmatch(r'[a-f0-9]{40}',sha): errors.append('app_sha_unavailable')
    return dict(schema='dualguard-ec2-db-v1',run_id=run_id,started_at=value.get('started_at'),
        ended_at=value.get('ended_at'),app_sha=sha,sections=sections,commands=commands,
        collection_status='INCOMPLETE' if errors else 'COLLECTED',errors=sorted(set(errors)))


class SSHDatabase:
    def __init__(self,settings,*,run=None):
        self.settings,self.run=settings,run or subprocess.run

    def collect(self,run_id=None,*,allow_root=True,root_password=None):
        queries(run_id)  # 전송 전에 입력 검증. 임의 SQL 입력은 받지 않는다.
        if root_password is not None and (not isinstance(root_password,str) or not root_password
                or len(root_password)>512 or any(c in root_password for c in '\r\n\x00') or not allow_root):
            raise ValueError('숨김 입력 인증 값의 형식을 확인하세요.')
        source='\n'.join((HERE/name).read_text(encoding='utf-8') for name in
            ('ec2_collection_worker.py','ec2_db_queries.py','ec2_db_worker.py'))
        source+='\ndb_main('+repr(run_id)+','+repr(allow_root)+','+repr(root_password)+')\n'
        start=time.perf_counter()
        transport=dict(check='ssh_database',started_at=now(),status='UNAVAILABLE',exit_code=None,timeout_seconds=200)
        result=None
        try:
            response=self.run(self.settings.argv(),input=source,text=True,encoding='utf-8',errors='strict',
                              capture_output=True,timeout=200,shell=False)
            transport['exit_code']=response.returncode
            if response.returncode: transport['status']='SSH_FAILED'
            elif len(response.stdout.encode('utf-8'))>4*1024*1024: transport['status']='OUTPUT_LIMIT'
            else:
                result=parse_db_observation(json.loads(response.stdout),run_id)
                transport['status']='OK'
        except subprocess.TimeoutExpired: transport['status']='TIMEOUT'
        except (ValueError,TypeError,KeyError,UnicodeError): transport['status']='INVALID_OUTPUT'
        except OSError: transport['status']='UNAVAILABLE'
        transport.update(ended_at=now(),elapsed_ms=(time.perf_counter()-start)*1000)
        if result is None:
            result=dict(schema='dualguard-ec2-db-v1',run_id=run_id,collection_status='INCOMPLETE',
                sections={k:dict(status='UNAVAILABLE',rows=None,authentication=None) for k in FIELDS},
                commands=[],errors=[transport['status']])
        result['transport']=transport
        return result


def section_rows(snapshot,name):
    return snapshot.get('sections',{}).get(name,{}).get('rows')


def compare(before,after):
    """누적 계수의 차이만 비교한다. 전체 기간 평균·최대를 구간 통계로 사용하지 않는다."""
    errors=[]
    if before.get('run_id')!=after.get('run_id'): errors.append('outbox_run_scope_mismatch')
    old_meta,new_meta=section_rows(before,'metadata'),section_rows(after,'metadata')
    old_status,new_status=section_rows(before,'status'),section_rows(after,'status')
    b={r['name']:r['value'] for r in old_status or []}
    a={r['name']:r['value'] for r in new_status or []}
    identity_ok=(old_meta and new_meta and old_meta[0].get('server_hash')==new_meta[0].get('server_hash')
                 and 'Uptime' in b and 'Uptime' in a and a['Uptime']>=b['Uptime'])
    if not identity_ok: errors.append('server_identity_or_uptime_unconfirmed')
    status_delta={}
    for key in STATUS_NAMES:
        if key in GAUGES:
            status_delta[key]=dict(before=b.get(key),after=a.get(key),kind='gauge')
        elif key not in a or key not in b or not identity_ok:
            status_delta[key]=dict(delta=None,kind='counter',reason='unavailable')
        elif a[key]<b[key]:
            status_delta[key]=dict(delta=None,kind='counter',reason='counter_reset')
            errors.append('global_counter_reset:'+key)
        else: status_delta[key]=dict(delta=a[key]-b[key],kind='counter')
    digest_delta=[]
    br,ar=section_rows(before,'digests'),section_rows(after,'digests')
    digest_complete=(br is not None and ar is not None and len(br)<=2000 and len(ar)<=2000
                     and not any(r.get('digest') is None for r in br+ar))
    if not digest_complete: errors.append('digest_snapshot_incomplete')
    old={r['digest']:r for r in br or [] if r.get('digest')}
    new={r['digest']:r for r in ar or [] if r.get('digest')}
    for digest,row in new.items():
        prev=old.get(digest)
        valid=identity_ok and digest_complete and (prev is None or prev.get('first_seen')==row.get('first_seen'))
        deltas={k:row[k]-(prev[k] if prev else 0) for k in DIGEST_COUNTERS} if valid else None
        if deltas is not None and any(v<0 for v in deltas.values()): valid=False
        if not valid:
            errors.append('digest_reset_or_unconfirmed:'+digest)
            digest_delta.append(dict(digest=digest,delta=None))
            continue
        count=deltas['count']
        digest_delta.append(dict(digest=digest,verb=row['verb'],tables=[t for t in row['tables'] if t],
            observer_candidate=bool(row['observer_candidate']),delta=deltas,
            total_ms=deltas['timer_ps']/1_000_000_000,
            mean_ms=deltas['timer_ps']/1_000_000_000/count if count else None,
            rows_examined_per_call=deltas['rows_examined']/count if count else None))
    if old.keys()-new.keys(): errors.append('digest_rows_disappeared')
    digest_delta.sort(key=lambda r:r.get('total_ms',-1),reverse=True)
    old_outbox,new_outbox=section_rows(before,'outbox'),section_rows(after,'outbox')
    publication=dict(count=None,mean_ms=None,status='UNAVAILABLE')
    if old_outbox is not None and new_outbox is not None and identity_ok and before.get('run_id')==after.get('run_id'):
        invalid=sum(r.get('invalid_time_count') or 0 for r in old_outbox+new_outbox)
        count=sum(r['published_count'] for r in new_outbox)-sum(r['published_count'] for r in old_outbox)
        us=sum(r.get('publish_sum_us') or 0 for r in new_outbox)-sum(r.get('publish_sum_us') or 0 for r in old_outbox)
        if invalid or count<0 or us<0 or (count==0 and us!=0):
            publication['status']='RESET_OR_INVALID_TIME'
            errors.append('outbox_publication_unconfirmed')
        else:
            publication=dict(count=count,mean_ms=us/1000/count if count else None,status='NO_NEW_PUBLICATIONS' if count==0 else 'OBSERVED_DELTA')
    return dict(scope='whole_database_interval_including_observers_and_background',status_delta=status_delta,
        digest_delta=digest_delta,outbox_publication=publication,
        comparison_status='INCOMPLETE' if errors else 'COMPARABLE',errors=sorted(set(errors)))
