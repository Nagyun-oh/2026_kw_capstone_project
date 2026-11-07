"""P7 전용 원격 동작. 조회와 WAF 단일 서비스의 임시 제외 원복만 지원한다.

ec2_collection_worker.py와 함께 SSH 표준 입력으로 실행한다.
반환값에 발생기 IP가 있으므로 클라이언트는 private-state.json에만 저장한다.
"""
import ipaddress


def validate_exclusions(value):
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError('EXCLUSION_FORMAT')
    for item in value.replace(',', ' ').split():
        ipaddress.ip_address(item)
    return value


def inspect_connection(runner, source, request_id=None):
    ids = discover(runner)
    if set(ids) != SERVICES:
        raise ValueError('SERVICES_MISSING')
    head = runner.run('app_sha', ['git', 'rev-parse', 'HEAD'])
    state = runner.run('waf_state', ['sudo', '-n', 'docker', 'inspect', '--format',
        '{"id":{{json .Id}},"health":{{with index .State "Health"}}{{json .Status}}{{else}}null{{end}},"running":{{.State.Running}}}', ids['waf']])
    exclude = runner.run('waf_exclusions', ['sudo', '-n', 'docker', 'inspect', '--format',
        '{{range .Config.Env}}{{println .}}{{end}}', ids['waf']],
        transform=lambda line: line.split('=', 1)[1] if line.startswith('WAF_SYNC_EXCLUDE_IPS=') else None)
    if head is None or state is None or exclude is None:
        raise ValueError('INSPECT_FAILED')
    validate_exclusions(exclude)
    test = runner.run('nginx_test', ['sudo', '-n', 'docker', 'exec', ids['waf'], 'nginx', '-t'],
        transform=lambda line: None)
    ip_hex = source.encode().hex()
    query = f"""SET SESSION MAX_EXECUTION_TIME=3000;
START TRANSACTION READ ONLY;
SELECT JSON_OBJECT('id',b.id,'threatId',b.source_threat_id,'requestId',n.request_id,
 'runId',JSON_UNQUOTE(JSON_EXTRACT(IF(JSON_VALID(n.raw_log),n.raw_log,'{{}}'),'$.test_run')))
FROM ip_blacklist b LEFT JOIN detected_threats t ON t.id=b.source_threat_id
LEFT JOIN network_logs n ON n.id=t.log_id
WHERE b.ip_address=CONVERT(0x{ip_hex} USING utf8mb4);
ROLLBACK;"""
    shell = ('test -n "$MYSQL_USER" && MYSQL_PWD="$MYSQL_PASSWORD" exec mysql -u "$MYSQL_USER" '
        '-D security_db --connect-timeout=3 --default-character-set=utf8mb4 --batch --raw --skip-column-names')
    rows = runner.run('source_blacklist', ['sudo', '-n', 'docker', 'exec', '-i', ids['db'], 'sh', '-c', shell], input_text=query)
    if rows is None:
        raise ValueError('BLACKLIST_QUERY_FAILED')
    result = dict(source_ipv4=source, exclusions=exclude, app_sha=head.strip(),
        waf=json.loads(state), nginx_test_ok=test is not None,
        blacklist=[json.loads(line) for line in rows.splitlines() if line.strip()])
    if request_id is not None:
        if not re.fullmatch(r'[a-fA-F0-9]{32}', request_id):
            raise ValueError('REQUEST_ID_FORMAT')
        query = f"""SET SESSION MAX_EXECUTION_TIME=3000;
SELECT JSON_OBJECT('rows',COUNT(*),'matches',COALESCE(SUM(ip_address=CONVERT(0x{ip_hex} USING utf8mb4)),0))
FROM network_logs WHERE BINARY request_id=BINARY '{request_id}';"""
        match = runner.run('https_source_match', ['sudo', '-n', 'docker', 'exec', '-i', ids['db'], 'sh', '-c', shell], input_text=query)
        if match is None:
            raise ValueError('SOURCE_QUERY_FAILED')
        result['https_source'] = json.loads(match)
    return result


def connection_main(config):
    runner = Runner()
    result = dict(schema='dualguard-ec2-connection-control-v1', at=now(), commands=runner.commands)
    try:
        source = os.environ.get('SSH_CONNECTION', '').split()[0]
        if not ipaddress.ip_address(source).is_global or ipaddress.ip_address(source).version != 4:
            raise ValueError('PUBLIC_IPV4_REQUIRED')
        if config.get('source_ipv4') is not None and config['source_ipv4'] != source:
            raise ValueError('SOURCE_CHANGED')
        before = inspect_connection(runner, source, config.get('request_id'))
        result['private'] = before
        if config['action'] == 'reconfigure':
            expected = validate_exclusions(config['expected_exclusions'])
            desired = validate_exclusions(config['desired_exclusions'])
            old_items = set(expected.replace(',', ' ').split())
            new_items = set(desired.replace(',', ' ').split())
            if (old_items ^ new_items) - {source}:
                raise ValueError('ONLY_GENERATOR_EXCLUSION_MAY_CHANGE')
            if before['app_sha'] != config['expected_sha']:
                raise ValueError('APP_CHANGED')
            if before['exclusions'] != expected or before['waf']['id'] != config['expected_waf_id']:
                raise ValueError('CONFIG_CHANGED')
            if not before['nginx_test_ok']:
                raise ValueError('BASELINE_NGINX_INVALID')
            result['reconfigure_attempted'] = True
            # .env.aws는 수정하지 않는다. 기존 목록 전체를 보존한 단일 변수만 덮어쓴다.
            output = runner.run('recreate_waf', ['sudo', '-n', 'env', 'WAF_SYNC_EXCLUDE_IPS='+desired,
                'docker', 'compose', '--env-file', '.env.aws', '-f', 'compose.aws.yaml',
                'up', '-d', '--force-recreate', '--no-deps', 'waf'], timeout=90,
                transform=lambda line: None)
            result['command_succeeded'] = output is not None
            # timeout도 성공으로 위장하지 않는다. 다음 inspect에서 실제 상태를 재확인한다.
        elif config['action'] != 'inspect':
            raise ValueError('ACTION_NOT_ALLOWED')
        result['status'] = 'OK'
    except Exception as error:
        result.update(status='FAILED', error_code=str(error) if type(error) is ValueError else type(error).__name__)
    print(json.dumps(result, separators=(',', ':')))
