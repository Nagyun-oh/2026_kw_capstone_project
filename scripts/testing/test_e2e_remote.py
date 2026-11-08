import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

from ec2_collection_worker import Runner, collect, discover, lag_line, trace_filter
from e2e_core import parse_traces
from e2e_environment import select_environment
from e2e_remote import SCHEMA, SSHCollection, SSHSettings, parse_collection, worker_request, worker_script
from metrics import resource_peaks
from pipeline import zero_lag
from run_ec2_collection import main
from run_e2e import Experiment

RID='a'*32
OTHER='b'*32
SINCE='2026-11-05T06:48:00Z'
STREAMS=[('log-group','log-topic'),('ai-service-group','ai-request-topic'),
         ('ai-result-group','ai-result-topic'),('waf-detection-group','waf-detection-topic')]


def lag_text(value='0'):
    return 'GROUP TOPIC PARTITION CURRENT-OFFSET LOG-END-OFFSET LAG\n'+'\n'.join(
        f'{g} {t} 0 10 10 {value}' for g,t in STREAMS)


def trace(rid=RID):
    return dict(schema='dualguard-trace-v1',stage='LOG_COMMITTED',outcome='CREATED',requestId=rid,
        logId=1,threatId=None,alertId=None,revision=None,sources=[],at=SINCE)


def response(config, *, rows=None):
    db=dict(requestId=RID,logId=1,phase='measurement',kind='background',sequence='1',ingress='1793861280.000',
        alertId=None,revision=None,aiDetected=0,wafDetected=0,aiRows=0,wafRows=0)
    return dict(schema=SCHEMA,mode=config['mode'],run_id=config['run_id'],load_generated=False,app_sha='a'*40,
        started_at=SINCE,ended_at=SINCE,lag_text=lag_text(),
        database_text='\n'.join(json.dumps(r) for r in ([db] if rows is None else rows)),
        trace_text='DG_TRACE '+json.dumps(trace()) if rows is None or config['request_ids'] else '',
        trace_enabled=True,errors=[],missing_services=[],log_id_floor='36475',
        resources=dict(at=SINCE,containers=[dict(Name='backend',CPUPerc='150.2%',MemPerc='8.5%',MemUsage='100MiB / 1GiB')],
            states=[dict(service='backend',image_id='sha256:test',state='running',health=None,restart_count=0,started_at=SINCE)]),
        commands=[dict(check=k,status='OK',exit_code=0,elapsed_ms=3) for k in (
            'containers_discover','kafka_lag','database','trace_enabled','pipeline_traces','containers_state','docker_stats')])


class RemoteCollectionTests(unittest.TestCase):
    def settings(self):
        return SSHSettings('example.test',Path('private-key'),'verified-host.test')

    def test_ssh_keeps_host_key_checks_and_does_not_echo_private_settings(self):
        settings=self.settings()
        args=settings.argv()
        self.assertIn('StrictHostKeyChecking=yes',args)
        self.assertIn('UpdateHostKeys=no',args)
        self.assertIn('IdentitiesOnly=yes',args)
        self.assertEqual(args[-1],'python3 -')
        self.assertNotIn('private-key',repr(settings))
        self.assertNotIn('example.test',repr(settings))

    def test_ssh_settings_reject_option_and_shell_injection(self):
        for value in ('-oProxyCommand=bad','x;bad','x\nbad','user@host','host/path',''):
            with self.subTest(value=value),self.assertRaises(ValueError):
                SSHSettings(value,Path('key'))

    def test_request_validation_runs_before_transport_and_query_uses_hex(self):
        config=worker_request('run-id',SINCE,[RID],'check')
        self.assertIn('SET SESSION MAX_EXECUTION_TIME=3000;',config['database_sql'])
        self.assertIn('START TRANSACTION READ ONLY;',config['database_sql'])
        self.assertTrue(config['database_sql'].rstrip().endswith('ROLLBACK;'))
        self.assertNotRegex(config['database_sql'],r'(?i)\b(INSERT|UPDATE|DELETE|ALTER|CREATE|DROP)\b')
        self.assertIn('main(',worker_script(config))
        for run_id,since,ids in [('bad\n',SINCE,[]),('x','5m',[]),('x',SINCE,['no-id']),('x',SINCE,RID)]:
            with self.subTest(run=run_id,since=since),self.assertRaises(ValueError):
                worker_request(run_id,since,ids)

    def test_lag_filter_removes_hosts_and_preserves_unknown(self):
        header='GROUP TOPIC PARTITION CURRENT-OFFSET LOG-END-OFFSET LAG CONSUMER-ID HOST CLIENT-ID'
        self.assertEqual(len(lag_line(header).split()),6)
        value=lag_line('log-group log-topic 0 - 5 - consumer /172.18.0.8 private')
        self.assertEqual(value,'log-group log-topic 0 - 5 -')
        self.assertIsNone(lag_line('private-error private-host password'))
        config=worker_request('run',SINCE,[],'check')
        data=response(config)
        data['lag_text']=lag_text('-')
        parsed=parse_collection(data,config)
        self.assertEqual(parsed['collection_status'],'INCOMPLETE')
        self.assertIsNone(parsed['lag']['rows'][0]['lag'])
        self.assertFalse(zero_lag(parsed['lag'],set()))

    def test_trace_filter_only_returns_matching_request_and_whitelisted_fields(self):
        errors=set()
        keep=trace_filter({RID},errors)
        point=dict(trace(),ip='private-ip',body='private-body',token='private-token')
        result=keep('backend | DG_TRACE '+json.dumps(point))
        self.assertEqual(parse_traces(result)[0]['requestId'],RID)
        self.assertNotIn('private-',result)
        self.assertIsNone(keep('DG_TRACE '+json.dumps(trace(OTHER))))
        self.assertIsNone(keep('ordinary private-token'))
        self.assertIsNone(keep('DG_TRACE_UNAVAILABLE stage=LOG_COMMITTED'))
        self.assertEqual(errors,{'TRACE_WRITE_FAILED'})

    def test_malformed_matching_trace_is_not_silently_ignored(self):
        with self.assertRaises(ValueError):
            trace_filter({RID},set())('DG_TRACE {"requestId":"'+RID+'",')

    def test_parsers_preserve_empty_queries_as_known_empty_but_missing_as_unknown(self):
        config=worker_request('run',SINCE,[],'check')
        value=response(config,rows=[])
        result=parse_collection(value,config)
        self.assertEqual(result['collection_status'],'COLLECTED')
        self.assertEqual(result['database'],[])
        self.assertEqual(result['traces'],[])
        value['database_text']=None
        result=parse_collection(value,config)
        self.assertIsNone(result['database'])
        self.assertIn('DATABASE_UNAVAILABLE',result['errors'])

    def test_lost_partition_or_group_is_incomplete(self):
        config=worker_request('run',SINCE,[],'check')
        value=response(config)
        result=parse_collection(value,config,{('log-group','log-topic',1)})
        self.assertIn('LAG_INCOMPLETE',result['errors'])
        value['lag_text']=''
        self.assertIn('LAG_INCOMPLETE',parse_collection(value,config)['errors'])

    def test_cpu_over_100_and_null_health_are_preserved(self):
        config=worker_request('run',SINCE,[],'check')
        result=parse_collection(response(config),config)
        self.assertIsNone(result['resources']['states'][0]['health'])
        self.assertEqual(resource_peaks([result['resources']])['backend']['cpu_percent_max'],150.2)

    def test_resource_nan_and_missing_state_are_invalid(self):
        config=worker_request('run',SINCE,[],'check')
        value=response(config)
        value['resources']['containers'][0]['CPUPerc']='NaN%'
        with self.assertRaises(ValueError): parse_collection(value,config)
        value=response(config)
        value['resources']['states']=[]
        with self.assertRaises(ValueError): parse_collection(value,config)

    def test_command_failures_tail_limit_and_trace_disabled_prevent_complete(self):
        config=worker_request('run',SINCE,[],'check')
        value=response(config)
        value['commands'][0].update(status='TIMEOUT',exit_code=None,stderr='private-error')
        value.update(trace_enabled=False,errors=['TRACE_TAIL_LIMIT'])
        result=parse_collection(value,config)
        self.assertEqual(result['collection_status'],'INCOMPLETE')
        self.assertIn('TRACE_TAIL_LIMIT',result['errors'])
        self.assertIn('TRACE_NOT_ENABLED',result['errors'])
        self.assertNotIn('private-error',json.dumps(result))

    def test_check_collection_returns_log_id_floor_and_later_queries_use_it(self):
        config=worker_request('run',SINCE,[],'check')
        self.assertEqual(parse_collection(response(config),config)['log_id_floor'],36475)
        for bad in (None,'-1','12 OR 1=1',36475):
            value=response(config);value['log_id_floor']=bad
            result=parse_collection(value,config)
            self.assertIn('LOG_ID_FLOOR_UNAVAILABLE',result['errors'])
            self.assertNotIn('log_id_floor',result)
        self.assertIn('n.id > 36475 AND',worker_request('run',SINCE,[RID],'pipeline',log_id_floor=36475)['database_sql'])
        self.assertNotIn('n.id >',config['database_sql'])
        pipeline=worker_request('run',SINCE,[],'pipeline')
        self.assertNotIn('LOG_ID_FLOOR_UNAVAILABLE',parse_collection(response(pipeline),pipeline)['errors'])

    def test_failure_classification_codes_pass_but_any_other_text_is_dropped(self):
        config=worker_request('run',SINCE,[],'pipeline')
        value=response(config)
        value['commands'][2].update(status='COMMAND_FAILED',exit_code=1,error_codes=['2013/HY000'])
        value['commands'][3].update(error_codes=["Lost connection to MySQL server at 'private-host'"])
        value['commands'][4].update(error_codes=['OTHER']*6)
        result=parse_collection(value,config)
        commands={c['check']:c for c in result['commands']}
        self.assertEqual(commands['database']['error_codes'],['2013/HY000'])
        self.assertNotIn('error_codes',commands['trace_enabled'])
        self.assertNotIn('error_codes',commands['pipeline_traces'])
        self.assertNotIn('private-host',json.dumps(result))

    def test_unrelated_trace_returned_by_remote_is_rejected(self):
        config=worker_request('run',SINCE,[],'check')
        value=response(config,rows=[])
        value['trace_text']='DG_TRACE '+json.dumps(trace(OTHER))
        with self.assertRaises(ValueError): parse_collection(value,config)

    def test_ssh_failures_timeout_and_bad_json_never_expose_output(self):
        scenarios=[subprocess.CompletedProcess([],255,'private-stdout','private-stderr'),
                   subprocess.TimeoutExpired('private-command',80,output='private-stdout'),
                   subprocess.CompletedProcess([],0,'private-not-json','private-stderr'),
                   FileNotFoundError('private-path')]
        for fake in scenarios:
            run=Mock(side_effect=fake) if isinstance(fake,Exception) else Mock(return_value=fake)
            adapter=SSHCollection(self.settings(),run=run)
            result=adapter.collect('run',SINCE,mode='check')
            self.assertEqual(result['collection_status'],'INCOMPLETE')
            self.assertIsNone(result['lag'])
            self.assertNotIn('private-',json.dumps(result))
            self.assertFalse(run.call_args.kwargs['shell'])
            self.assertEqual(run.call_args.kwargs['timeout'],80)

    def test_adapter_parses_success_and_keeps_command_timing(self):
        config=worker_request('run',SINCE,[],'check')
        run=Mock(return_value=subprocess.CompletedProcess([],0,json.dumps(response(config)),''))
        result=SSHCollection(self.settings(),run=run).collect('run',SINCE,mode='check')
        self.assertEqual(result['collection_status'],'COLLECTED')
        self.assertEqual(result['transport']['status'],'OK')
        self.assertEqual(len(result['commands']),7)
        self.assertNotIn('example.test',json.dumps(result))

    def test_worker_limits_and_failures_are_kept_without_raw_errors(self):
        runner=Runner()
        with patch('ec2_collection_worker.subprocess.Popen',side_effect=OSError('private-error')):
            self.assertIsNone(runner.run('db',['fake']))
        self.assertEqual(runner.commands[0]['status'],'UNAVAILABLE')
        self.assertNotIn('private-error',json.dumps(runner.commands))

    def failed_query(self, stderr, **options):
        runner=Runner()
        proc=Mock(pid=4321,returncode=1)
        proc.poll.return_value=1
        proc.wait.return_value=1
        selector=Mock()
        selector.get_map.return_value={}
        def popen(argv,**kwargs):
            if kwargs['stderr'] not in (subprocess.DEVNULL,subprocess.STDOUT):
                kwargs['stderr'].write(stderr)
            return proc
        with patch('ec2_collection_worker.subprocess.Popen',side_effect=popen), \
                patch('ec2_collection_worker.selectors.DefaultSelector') as selectors:
            selectors.return_value.__enter__.return_value=selector
            self.assertIsNone(runner.run('database',['fake'],**options))
        return runner.commands[0]

    def test_failed_database_query_keeps_only_error_classification(self):
        message=b"ERROR 2013 (HY000): Lost connection to MySQL server at 'private-host', system error: 110\n"
        item=self.failed_query(message,classify_errors=True)
        self.assertEqual((item['status'],item['exit_code'],item['error_codes']),('COMMAND_FAILED',1,['2013/HY000']))
        self.assertNotIn('private-host',json.dumps(item))
        self.assertNotIn('Lost connection',json.dumps(item))
        self.assertEqual(self.failed_query(b'',classify_errors=True)['error_codes'],['NO_STDERR'])
        self.assertEqual(self.failed_query(b'private detail',classify_errors=True)['error_codes'],['OTHER'])
        self.assertEqual(self.failed_query(b'Error response from daemon: private',classify_errors=True)['error_codes'],
                         ['DOCKER_DAEMON'])
        self.assertNotIn('error_codes',self.failed_query(message))

    def test_worker_timeout_terminates_only_its_own_query_process_group(self):
        runner=Runner()
        proc=Mock(pid=4321,returncode=None)
        proc.poll.return_value=None
        selector=Mock()
        selector.get_map.return_value={1:True}
        with patch('ec2_collection_worker.subprocess.Popen',return_value=proc), \
                patch('ec2_collection_worker.selectors.DefaultSelector') as selectors, \
                patch('ec2_collection_worker.time.monotonic',side_effect=[0,2,3]), \
                patch('ec2_collection_worker.signal.SIGKILL',9,create=True), \
                patch('ec2_collection_worker.os.killpg',create=True) as kill:
            selectors.return_value.__enter__.return_value=selector
            self.assertIsNone(runner.run('query',['fake'],timeout=1))
        self.assertEqual(runner.commands[0]['status'],'TIMEOUT')
        self.assertEqual(kill.call_args.args[0],4321)
        proc.wait.assert_called_once()

    def test_worker_output_limit_discards_partial_results_and_terminates_own_query(self):
        runner=Runner()
        proc=Mock(pid=4321,returncode=None)
        proc.poll.return_value=None
        selector=Mock()
        selector.get_map.return_value={1:True}
        selector.select.return_value=[1]
        with patch('ec2_collection_worker.subprocess.Popen',return_value=proc), \
                patch('ec2_collection_worker.selectors.DefaultSelector') as selectors, \
                patch('ec2_collection_worker.os.read',return_value=b'private-oversized-output'), \
                patch('ec2_collection_worker.signal.SIGKILL',9,create=True), \
                patch('ec2_collection_worker.os.killpg',create=True) as kill:
            selectors.return_value.__enter__.return_value=selector
            self.assertIsNone(runner.run('query',['fake'],max_bytes=2))
        self.assertEqual(runner.commands[0]['status'],'OUTPUT_LIMIT')
        self.assertNotIn('private-',json.dumps(runner.commands))
        self.assertEqual(kill.call_args.args[0],4321)

    def test_worker_queries_only_selected_project_and_never_full_env_or_compose_config(self):
        runner=Mock(commands=[])
        runner.run.return_value=''
        self.assertEqual(discover(runner),{})
        self.assertIn('label=com.docker.compose.project=security-platform-aws',runner.run.call_args.args[1])
        self.assertNotIn('config',runner.run.call_args.args[1])

    def test_worker_uses_app_auth_read_only_sql_and_filters_before_sending(self):
        config=worker_request('run',SINCE,[RID],'check')
        runner=Mock(commands=[])
        calls=[]
        services=('backend','db','kafka')
        def run(label,argv,**kwargs):
            calls.append((label,argv,kwargs))
            runner.commands.append(dict(check=label,status='OK',lines_read=1))
            if label=='containers_discover':
                return '\n'.join(json.dumps(dict(service=s,id=str(i+1)*64)) for i,s in enumerate(services))
            if label=='trace_enabled': return 'true'
            return ''
        runner.run.side_effect=run
        result=collect(config,runner)
        db=next(c for c in calls if c[0]=='database')
        self.assertIn('MYSQL_PWD="$MYSQL_PASSWORD"',db[1][-1])
        self.assertIn('START TRANSACTION READ ONLY;',db[2]['input_text'])
        self.assertIn('MAX_EXECUTION_TIME=3000',db[2]['input_text'])
        logs=next(c for c in calls if c[0]=='pipeline_traces')
        self.assertTrue(logs[2]['merge_stderr'])
        self.assertIsNone(logs[2]['transform']('ordinary private-body'))
        self.assertEqual(result['trace_text'],'')
        # check 수집은 같은 앱 계정으로 최대 로그 id만 읽는다(기본 키 조회, 숫자 외 출력은 버림).
        floor=next(c for c in calls if c[0]=='log_id_floor')
        self.assertEqual(floor[1],db[1])
        self.assertIn('SELECT COALESCE(MAX(id),0) FROM network_logs;',floor[2]['input_text'])
        self.assertIn('MAX_EXECUTION_TIME=3000',floor[2]['input_text'])
        self.assertEqual(floor[2]['transform']('36475'),'36475')
        self.assertIsNone(floor[2]['transform']('private text'))
        calls.clear();runner.commands.clear()
        collect(worker_request('run',SINCE,[RID],'pipeline'),runner)
        self.assertNotIn('log_id_floor',[c[0] for c in calls])

    def test_lag_can_be_skipped_only_in_pipeline_collection(self):
        self.assertTrue(worker_request('run',SINCE,[RID],'pipeline')['include_lag'])
        self.assertFalse(worker_request('run',SINCE,[RID],'pipeline',False)['include_lag'])
        for mode in ('check','resources'):
            with self.assertRaises(ValueError): worker_request('run',SINCE,[RID],mode,False)
        with self.assertRaises(ValueError): worker_request('run',SINCE,[RID],'pipeline','no')

    def test_skipped_lag_is_not_a_failure_but_unrequested_lag_is_rejected(self):
        config=worker_request('run',SINCE,[RID],'pipeline',False)
        value=response(config)
        value['lag_text']=None
        result=parse_collection(value,config)
        self.assertEqual(result['collection_status'],'COLLECTED')
        self.assertIsNone(result['lag'])
        self.assertEqual(result['traces'][0]['requestId'],RID)
        unexpected=parse_collection(response(config),config)
        self.assertEqual(unexpected['collection_status'],'INCOMPLETE')
        self.assertIn('LAG_NOT_REQUESTED',unexpected['errors'])

    def test_worker_runs_lag_cli_only_when_requested(self):
        for include_lag in (True,False):
            config=worker_request('run',SINCE,[RID],'pipeline',include_lag)
            runner=Mock(commands=[])
            labels=[]
            def run(label,argv,**kwargs):
                labels.append(label)
                runner.commands.append(dict(check=label,status='OK',lines_read=1))
                if label=='containers_discover':
                    return '\n'.join(json.dumps(dict(service=s,id=str(i+1)*64)) for i,s in enumerate(('backend','db','kafka')))
                if label=='trace_enabled': return 'true'
                return ''
            runner.run.side_effect=run
            result=collect(config,runner)
            self.assertEqual('kafka_lag' in labels,include_lag)
            self.assertIn('database',labels)
            self.assertIn('pipeline_traces',labels)
            if not include_lag: self.assertIsNone(result['lag_text'])

    def test_dry_run_never_reserves_files_runs_ssh_or_load(self):
        with patch('run_ec2_collection.reserve') as reserve,patch('e2e_remote.subprocess.run') as run, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['--dry-run','--since',SINCE]),0)
        reserve.assert_not_called()
        run.assert_not_called()

    def test_collection_cli_saves_failures_and_report_without_overwriting(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            key=root/'key'
            key.write_text('test-only-key',encoding='utf-8')
            result=dict(collection_status='INCOMPLETE',errors=['TIMEOUT'],lag=None,database=None,traces=None,
                        resources=None,commands=[],transport=dict(status='TIMEOUT',elapsed_ms=3))
            argv=['--collect-only','--since',SINCE,'--ssh-host','example.test','--identity-file',str(key)]
            with patch('run_ec2_collection.ROOT',root),patch('run_ec2_collection.SSHCollection') as adapter, \
                    patch('run_ec2_collection.local_git_state',return_value=dict(runner_head='a'*40,runner_working_tree_dirty=True)), \
                    contextlib.redirect_stdout(io.StringIO()):
                adapter.return_value.collect.return_value=result
                self.assertEqual(main(argv),1)
                manifest_path=next((root/'build/test-runs').glob('*/manifest.json'))
                manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
                self.assertEqual(manifest['collection_status'],'INCOMPLETE')
                self.assertFalse(manifest['load_generated'])
                self.assertNotIn('example.test',json.dumps(manifest))
                self.assertTrue(next((root/'docs/testing/ec2/runs').glob('*.md')).read_text(encoding='utf-8'))
                with self.assertRaises(FileExistsError): main(argv)


class RunnerIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_ec2_pipeline_and_resource_inputs_use_remote_adapter_without_local_commands(self):
        exp=object.__new__(Experiment)
        exp.environment=select_environment('ec2')
        exp.manifest=dict(id='run',started_at=SINCE)
        exp.clients=[dict(requestId=RID)]
        exp.keys=set()
        config=worker_request('run',SINCE,[RID],'check')
        value=parse_collection(response(config),config)
        value['transport']=dict(status='OK')
        exp.remote_collector=Mock()
        exp.remote_collector.collect.return_value=value
        exp.cmd=AsyncMock(side_effect=AssertionError('local command'))
        exp.append=Mock()
        lag,db,traces=await exp.pipeline_inputs()
        self.assertEqual(db[0]['requestId'],RID)
        self.assertEqual(traces[0]['requestId'],RID)
        resources=await exp.resource_input()
        self.assertEqual(resources['containers'][0]['Name'],'backend')
        exp.cmd.assert_not_called()
        self.assertEqual(exp.remote_collector.collect.call_count,2)

    async def test_collect_without_lag_keeps_traces_and_does_not_record_lag_sample(self):
        exp=object.__new__(Experiment)
        exp.environment=select_environment('ec2')
        exp.manifest=dict(id='run',started_at=SINCE)
        exp.clients=[dict(requestId=RID,phase='measurement')]
        exp.keys={('log-group','log-topic',0)}
        exp.snapshots=[]
        exp.traces,exp.trace_keys,exp.browser_events=[],set(),[]
        exp.previous_counts,exp.previous_progress_at={},0
        exp.page=None
        exp.output=Path(tempfile.mkdtemp())
        exp.guard=Mock()
        exp.append=Mock()
        exp.should_collect_lag=lambda:False
        config=worker_request('run',SINCE,[RID],'pipeline',False)
        value=response(config)
        value['lag_text']=None
        parsed=parse_collection(value,config)
        parsed['transport']=dict(status='OK')
        exp.remote_collector=Mock()
        exp.remote_collector.collect.return_value=parsed
        snap=await exp.collect()
        self.assertIsNone(snap)
        self.assertEqual(exp.snapshots,[])
        self.assertEqual(exp.remote_collector.collect.call_args.kwargs['include_lag'],False)
        self.assertEqual(exp.traces[0]['requestId'],RID)
        collected=[c.args for c in exp.guard.collected.call_args_list]
        self.assertNotIn(('kafka_lag',True),collected)
        self.assertIn(('pipeline',True),collected)

    async def test_incomplete_remote_result_cannot_be_used_as_normal_pipeline(self):
        exp=object.__new__(Experiment)
        exp.append=Mock()
        with self.assertRaises(RuntimeError):
            exp.record_remote_collection(dict(transport={},commands=[],collection_status='INCOMPLETE',errors=['TIMEOUT']))
        exp.append.assert_called_once()


if __name__=='__main__':
    unittest.main()
