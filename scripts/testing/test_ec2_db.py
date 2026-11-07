import contextlib
import copy
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock,patch

from ec2_db import SSHDatabase,compare,parse_db_observation
from ec2_db_queries import DIGEST_COUNTERS,FIELDS,STATUS_NAMES,TABLES,queries
from e2e_remote import SSHSettings
from run_ec2_db import main
from run_e2e import Experiment
from e2e_environment import select_environment


def row_digest(count=10,timer=10_000_000_000,first='2026-11-05 01:00:00'):
    row={key:0 for key in DIGEST_COUNTERS}
    row.update(digest='a'*64,verb='SELECT',tables=['network_logs',None],observer_candidate=0,
               first_seen=first,count=count,timer_ps=timer,rows_examined=count*20)
    return row


def raw():
    rows={key:[] for key in FIELDS}
    rows['metadata']=[dict(server_hash='b'*64,version='8.0.46',performance_schema=1)]
    rows['status']=[dict(name=key,value='100') for key in STATUS_NAMES]
    rows['instrumentation']=[dict(digest_consumer='YES',statement_consumer='YES',timed_statement_instruments=150)]
    rows['digests']=[row_digest()]
    rows['locks']=[dict(data_lock_waits=0,pending_metadata_locks=0)]
    rows['transactions']=[dict(active=0,lock_wait=0,oldest_ms=None,rows_locked=0,rows_modified=0)]
    rows['outbox']=[dict(state='SENT',count=1,max_attempts=1,ready_count=0,oldest_pending_ms=None,
        published_count=1,publish_sum_us=100_000,publish_max_us=100_000,invalid_time_count=0)]
    rows['tables']=[dict(table=name,estimated_rows=1,data_bytes=100,index_bytes=100) for name in TABLES]
    return dict(schema='dualguard-ec2-db-v1',run_id=None,load_generated=False,app_sha='c'*40,
        sections={key:dict(status='OK',rows=value,authentication='app_container_environment') for key,value in rows.items()},
        commands=[dict(check='db_'+key,status='OK',exit_code=0,elapsed_ms=10) for key in rows])


def snapshots():
    before=parse_db_observation(raw())
    after=copy.deepcopy(before)
    after['sections']['digests']['rows']=[row_digest(12,14_000_000_000)]
    return before,after


class DbObservationTests(unittest.TestCase):
    def test_queries_are_select_only_bounded_and_omit_sensitive_sql_fields(self):
        for name,query in queries().items():
            self.assertTrue(query.lstrip().startswith('SELECT'))
            self.assertLess(len(query.encode())+100,4096)
            self.assertNotIn('FOR UPDATE',query)
            self.assertNotIn('QUERY_SAMPLE_TEXT',query)
            self.assertNotIn('TRX_QUERY',query)
            self.assertNotIn('LOCK_DATA',query)
            self.assertNotIn('SQL_TEXT',query)
            self.assertNotIn('TRUNCATE',query)
            self.assertNotIn('GRANT',query)
        self.assertIn('LIMIT 2001',queries()['digests'])
        self.assertNotIn("'digest_text'",queries()['digests'])

    def test_outbox_run_scope_is_hex_encoded_and_utc_source_is_preserved(self):
        query=queries('run-01')['outbox']
        self.assertIn('72756e2d3031',query)
        self.assertIn('UTC_TIMESTAMP(6)',query)
        self.assertNotIn('INTERVAL 9',query)
        with self.assertRaises(ValueError): queries("x'; DROP TABLE x;")

    def test_success_null_transaction_age_and_empty_outbox_remain_distinct(self):
        value=raw()
        value['sections']['outbox']['rows']=[]
        result=parse_db_observation(value)
        self.assertEqual(result['collection_status'],'COLLECTED')
        self.assertEqual(result['sections']['outbox']['rows'],[])
        self.assertIsNone(result['sections']['transactions']['rows'][0]['oldest_ms'])
        value['sections']['outbox']=dict(status='COMMAND_FAILED',rows=None)
        result=parse_db_observation(value)
        self.assertIsNone(result['sections']['outbox']['rows'])
        self.assertIn('outbox_unavailable',result['errors'])

    def test_unexpected_private_fields_are_rejected(self):
        value=raw()
        value['sections']['digests']['rows'][0]['SQL_TEXT']='private-body'
        with self.assertRaises(ValueError): parse_db_observation(value)

    def test_digest_truncation_or_overflow_is_incomplete(self):
        value=raw()
        value['sections']['digests']['rows'][0]['digest']=None
        self.assertIn('digest_overflow_bucket',parse_db_observation(value)['errors'])
        before,after=snapshots()
        after['sections']['digests']['rows'][0]['digest']=None
        self.assertIn('digest_snapshot_incomplete',compare(before,after)['errors'])

    def test_disabled_instrumentation_is_not_a_clean_idle_database(self):
        value=raw()
        value['sections']['instrumentation']['rows'][0]['digest_consumer']='NO'
        self.assertEqual(parse_db_observation(value)['collection_status'],'INCOMPLETE')

    def test_missing_identity_is_rejected(self):
        value=raw()
        value['sections']['metadata']['rows'][0]['server_hash']=None
        with self.assertRaises(ValueError): parse_db_observation(value)

    def test_delta_uses_sum_and_count_instead_of_lifetime_average(self):
        before,after=snapshots()
        result=compare(before,after)
        row=result['digest_delta'][0]
        self.assertEqual(row['delta']['count'],2)
        self.assertEqual(row['total_ms'],4)
        self.assertEqual(row['mean_ms'],2)
        self.assertEqual(row['rows_examined_per_call'],20)

    def test_zero_calls_has_no_average_latency(self):
        before,after=snapshots()
        after=copy.deepcopy(before)
        self.assertIsNone(compare(before,after)['digest_delta'][0]['mean_ms'])

    def test_gauges_are_not_subtracted(self):
        before,after=snapshots()
        row=next(r for r in after['sections']['status']['rows'] if r['name']=='Threads_connected')
        row['value']=1
        value=compare(before,after)['status_delta']['Threads_connected']
        self.assertEqual(value,dict(before=100,after=1,kind='gauge'))

    def test_server_restart_or_identity_change_prevents_delta(self):
        for change in ('uptime','identity'):
            before,after=snapshots()
            if change=='uptime': next(r for r in after['sections']['status']['rows'] if r['name']=='Uptime')['value']=1
            else: after['sections']['metadata']['rows'][0]['server_hash']='d'*64
            result=compare(before,after)
            self.assertEqual(result['comparison_status'],'INCOMPLETE')
            self.assertIsNone(result['digest_delta'][0]['delta'])

    def test_digest_reset_first_seen_change_or_missing_rows_are_not_zero_work(self):
        for change in ('count','first_seen','missing'):
            before,after=snapshots()
            if change=='count': after['sections']['digests']['rows'][0]['count']=1
            if change=='first_seen': after['sections']['digests']['rows'][0]['first_seen']='new'
            if change=='missing': after['sections']['digests']['rows']=[]
            self.assertEqual(compare(before,after)['comparison_status'],'INCOMPLETE')

    def test_new_digest_uses_zero_baseline_only_with_complete_snapshot(self):
        before,after=snapshots()
        before['sections']['digests']['rows']=[]
        self.assertEqual(compare(before,after)['digest_delta'][0]['delta']['count'],12)
        before['sections']['digests']['rows']=None
        self.assertIsNone(compare(before,after)['digest_delta'][0]['delta'])

    def test_publication_delta_and_no_new_publication_are_distinct(self):
        before,after=snapshots()
        self.assertIsNone(compare(before,after)['outbox_publication']['mean_ms'])
        row=after['sections']['outbox']['rows'][0]
        row.update(count=3,published_count=3,publish_sum_us=500_000)
        publication=compare(before,after)['outbox_publication']
        self.assertEqual(publication['count'],2)
        self.assertEqual(publication['mean_ms'],200)

    def test_publication_reset_and_negative_timestamps_are_not_success(self):
        before,after=snapshots()
        after['sections']['outbox']['rows'][0]['invalid_time_count']=1
        self.assertEqual(compare(before,after)['outbox_publication']['status'],'RESET_OR_INVALID_TIME')

    def test_transport_failure_never_retains_secrets_or_returns_empty_success(self):
        settings=SSHSettings('example.test',Path('private-key'))
        for response in (subprocess.CompletedProcess([],1,'private-stdout','private-stderr'),
                         subprocess.CompletedProcess([],0,'private-not-json','')):
            run=Mock(return_value=response)
            result=SSHDatabase(settings,run=run).collect()
            self.assertEqual(result['collection_status'],'INCOMPLETE')
            self.assertNotIn('private-',json.dumps(result))
            self.assertFalse(run.call_args.kwargs['shell'])

    def test_prompt_password_is_only_in_ssh_stdin_not_arguments_or_result(self):
        password='test-only-private-password'
        run=Mock(return_value=subprocess.CompletedProcess([],0,json.dumps(raw()),''))
        result=SSHDatabase(SSHSettings('example.test',Path('key')),run=run).collect(root_password=password)
        self.assertEqual(result['collection_status'],'COLLECTED')
        self.assertNotIn(password,str(run.call_args.args[0]))
        self.assertIn(password,run.call_args.kwargs['input'])
        self.assertNotIn(password,json.dumps(result))
        for bad in ('','line\nbreak','nul\x00byte'):
            with self.assertRaises(ValueError): SSHDatabase(SSHSettings('example.test',Path('key')),run=run).collect(root_password=bad)

    def test_worker_prompt_password_is_not_in_mysql_command_arguments(self):
        import ec2_db_worker as worker
        runner=Mock(commands=[])
        password='test-only-private-password'
        calls=[]
        def run(label,argv,**kwargs):
            calls.append((label,argv,kwargs))
            runner.commands.append(dict(status='COMMAND_FAILED',check=label))
            if label=='app_sha': return 'c'*40
            if label.endswith('_app'):
                kwargs['transform']("ERROR 1142 (42000): private-error-account")
                return None
            return ''
        runner.run.side_effect=run
        with patch.object(worker,'Runner',return_value=runner,create=True), \
                patch.object(worker,'discover',return_value={'db':'container'},create=True), \
                patch.object(worker,'now',return_value='time',create=True), \
                patch.object(worker,'queries',return_value={'outbox':'SELECT 1;'},create=True), \
                patch.object(worker,'FIELDS',FIELDS,create=True),patch.object(worker,'re',__import__('re'),create=True):
            result=worker.db_collect(root_password=password)
        root=next(c for c in calls if c[0].endswith('_root'))
        self.assertNotIn(password,str(root[1]))
        self.assertTrue(root[2]['input_text'].startswith(password+'\nSET SESSION'))
        self.assertIn('IFS= read -r MYSQL_PWD',root[1][-1])
        self.assertNotIn(password,json.dumps(result))
        self.assertNotIn('private-error-account',json.dumps(result))

    def test_prompt_dry_run_does_not_read_password(self):
        with patch('run_ec2_db.getpass.getpass') as password,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['--dry-run','--prompt-db-root']),0)
        password.assert_not_called()

    def test_readonly_worker_reuses_runner_and_does_not_retry_timeouts_as_root(self):
        from ec2_collection_worker import Runner
        import ec2_db_worker as worker
        runner=Mock(commands=[])
        def run(label,argv,**kwargs):
            runner.commands.append(dict(status='TIMEOUT',check=label))
            if label=='app_sha': return 'c'*40
            return None
        runner.run.side_effect=run
        with patch.object(worker,'Runner',return_value=runner,create=True), \
                patch.object(worker,'discover',return_value={'db':'container'},create=True), \
                patch.object(worker,'now',return_value='time',create=True), \
                patch.object(worker,'queries',queries,create=True),patch.object(worker,'FIELDS',FIELDS,create=True):
            worker.db_collect()
        self.assertFalse(any('root' in call.args[0] for call in runner.run.call_args_list))
        for call in runner.run.call_args_list:
            if call.args[0]=='app_sha': continue
            sql=call.kwargs['input_text']
            self.assertIn('START TRANSACTION READ ONLY;',sql)
            self.assertIn('MAX_EXECUTION_TIME=3000;',sql)
            self.assertTrue(sql.rstrip().endswith('ROLLBACK;'))

    def test_dry_run_never_reserves_connects_or_sleeps(self):
        with patch('run_ec2_db.reserve') as reserve,patch('run_ec2_db.SSHDatabase') as ssh, \
                patch('run_ec2_db.time.sleep') as sleep,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['--dry-run']),0)
        reserve.assert_not_called()
        ssh.assert_not_called()
        sleep.assert_not_called()


class RunnerDatabaseIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_before_after_snapshots_and_delta_are_saved_outside_http_measurement(self):
        before,after=snapshots()
        with tempfile.TemporaryDirectory() as directory:
            exp=object.__new__(Experiment)
            exp.environment=select_environment('ec2')
            exp.output=Path(directory)
            exp.manifest=dict(id='run')
            exp.db_baseline=None
            exp.db_observer=Mock(side_effect=[before,after])
            await exp.database_observation('before')
            await exp.database_observation('after')
            result=json.loads((exp.output/'db-observation-comparison.json').read_text(encoding='utf-8'))
            self.assertEqual(result['comparison_status'],'COMPARABLE')
            self.assertEqual(exp.db_observer.call_count,2)

    async def test_local_execution_does_not_call_ec2_database_observer(self):
        exp=object.__new__(Experiment)
        exp.environment=select_environment('local')
        exp.db_observer=Mock(side_effect=AssertionError('remote access'))
        self.assertIsNone(await exp.database_observation('before'))
        exp.db_observer.assert_not_called()

    async def test_incomplete_database_snapshot_is_saved_then_stops(self):
        with tempfile.TemporaryDirectory() as directory:
            exp=object.__new__(Experiment)
            exp.environment=select_environment('ec2')
            exp.output=Path(directory)
            exp.manifest=dict(id='run')
            exp.db_observer=Mock(return_value=dict(collection_status='INCOMPLETE',errors=['denied']))
            with self.assertRaises(RuntimeError): await exp.database_observation('before')
            self.assertTrue((exp.output/'db-observation-before.json').exists())


if __name__=='__main__': unittest.main()
