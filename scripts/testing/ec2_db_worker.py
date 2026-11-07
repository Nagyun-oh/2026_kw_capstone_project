"""P6 서버 측 조회. P4 Runner·쿼리 목록과 함께 SSH 표준 입력으로 전달한다."""


def db_collect(run_id=None,allow_root=True,root_password=None):
    runner=Runner()
    result=dict(schema='dualguard-ec2-db-v1',started_at=now(),load_generated=False,
                run_id=run_id,sections={},commands=runner.commands)
    ids=discover(runner)
    cid=ids.get('db')
    head=runner.run('app_sha',['git','rev-parse','HEAD'])
    result['app_sha']=head.strip() if head is not None else None
    for name,query in queries(run_id).items():
        section=dict(status='UNAVAILABLE',rows=None,authentication=None,error_codes=[])
        result['sections'][name]=section
        if cid is None: continue
        for auth in (('app','root') if allow_root else ('app',)):
            login=('test -n "$MYSQL_USER" && MYSQL_PWD="$MYSQL_PASSWORD" exec mysql -u "$MYSQL_USER"'
                   if auth=='app' else 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql -u root')
            if auth=='root' and root_password is not None:
                login='IFS= read -r MYSQL_PWD && export MYSQL_PWD && exec mysql -u root'
            def keep(line):
                error=re.match(r'^ERROR\s+([0-9]+)\s+\(([A-Z0-9]+)\)',line)
                if error:
                    section['error_codes'].append(dict(authentication=auth,code=int(error[1]),sqlstate=error[2]))
                    return None
                if line.startswith('mysql: [Warning]'): return None
                row=json.loads(line)
                return json.dumps({k:row.get(k) for k in FIELDS[name]},separators=(',',':'))
            # 관측용 SQL은 세션의 읽기 전용 트랜잭션에서만 실행한다.
            sql='SET SESSION MAX_EXECUTION_TIME=3000;\nSTART TRANSACTION READ ONLY;\n'+query+'\nROLLBACK;\n'
            input_text=root_password+'\n'+sql if auth=='root' and root_password is not None else sql
            text=runner.run('db_'+name+'_'+auth,['sudo','-n','docker','exec','-i',cid,'sh','-c',
                login+' -D security_db --connect-timeout=3 --default-character-set=utf8mb4 --batch --raw --skip-column-names'],
                input_text=input_text,transform=keep,timeout=12,merge_stderr=True)
            if text is not None:
                source='root_prompt_memory' if auth=='root' and root_password is not None else auth+'_container_environment'
                section.update(status='OK',authentication=source,
                               rows=[json.loads(line) for line in text.splitlines()])
                break
            section['status']=runner.commands[-1]['status']
            if section['status'] in ('TIMEOUT','OUTPUT_LIMIT','LINE_LIMIT','INVALID_OUTPUT'):
                break
            if any(e['code'] in (1054,1064,1109,1146) for e in section['error_codes']):
                break  # 구문·컬럼·테이블 오류는 root로 재실행하지 않는다.
    result['ended_at']=now()
    return result


def db_main(run_id=None,allow_root=True,root_password=None):
    if os.name!='posix' or not (Path(REPO)/'compose.aws.yaml').is_file(): raise SystemExit(2)
    try: result=db_collect(run_id,allow_root,root_password)
    except Exception: result=dict(schema='dualguard-ec2-db-v1',fatal='DB_OBSERVATION_FAILED',load_generated=False)
    print(json.dumps(result,separators=(',',':')))
