import contextlib
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import Mock,patch

from ec2_watch import (Ec2Guard,WatchSession,calibrate,cpu_percent,ingress_in_clock_interval,
                       load_observation_policy,epoch_ms)
from e2e_core import client_record
from e2e_remote import SSHSettings
from run_ec2_watch import main


def exchange(base=1000,offset=350):
    return dict(client_sent_ms=base,client_received_ms=base+12,server_received_ms=base+5+offset,
        server_sent_ms=base+7+offset,roundtrip_ms=12,observed_monotonic=1)


def sample(policy,stamp=0,generator_gib=3,server_gib=4):
    mem=lambda n:dict(total_bytes=8*1024**3,available_bytes=int(n*1024**3))
    return dict(generator=dict(memory=mem(generator_gib),monotonic=stamp,cpu=dict(total=1000+int(stamp*20),idle=500+int(stamp*10))),
        server=dict(memory=mem(server_gib),monotonic=stamp,boot_sha256='a'*64,
            cpu=dict(user=100+int(stamp*10),nice=0,system=40,idle=400+int(stamp*10),iowait=0,irq=0,softirq=0,steal=int(stamp))),
        containers=[dict(id=s,service=s,running=True,oom_killed=False,health=None,restart_count=0,
                         started_at='2026-11-05T00:00:00Z') for s in policy['required_services']])


class ClockTests(unittest.TestCase):
    def test_precise_epoch_has_millisecond_units_on_posix(self):
        with patch('ec2_watch.sys.platform','linux'),patch('ec2_watch.time.time_ns',return_value=1234567890000000):
            self.assertEqual(epoch_ms(),1234567890.0)

    @unittest.skipUnless(sys.platform=='win32','Windows 정밀 UTC API 확인')
    def test_windows_precise_epoch_is_finer_than_15ms(self):
        values=[]
        started=time.perf_counter()
        while time.perf_counter()-started<.005:
            values.append(epoch_ms())
        self.assertGreater(len(set(values)),5)
        self.assertLess(abs(epoch_ms()-time.time()*1000),100)

    def test_watch_exchange_checks_sequence_and_never_returns_error_text(self):
        settings=SSHSettings('example.test',Path('key'))
        session=WatchSession(settings)
        session.process=Mock()
        session.process.stdin=io.BytesIO()
        session.responses.put(json.dumps(dict(schema='dualguard-ec2-watch-v1',op='clock',sequence=1,
            server_received_ms=1000,server_sent_ms=1001)).encode())
        result=session.exchange('clock')
        self.assertEqual(result['server_received_ms'],1000)
        session.responses.put(b'{"error":"private-error","sequence":99}')
        with patch.object(session,'close') as close:
            with self.assertRaisesRegex(RuntimeError,'^SSH_WATCH_FAILED$'):
                session.exchange('clock')
        close.assert_called_once()

    def test_watch_timeout_closes_session_and_does_not_reuse_late_response(self):
        settings=SSHSettings('example.test',Path('key'))
        session=WatchSession(settings)
        session.process=Mock()
        session.process.stdin=io.BytesIO()
        with patch.object(session,'close') as close:
            with self.assertRaises(RuntimeError): session.exchange('clock',timeout=.001)
        close.assert_called_once()

    def test_offset_is_an_interval_including_network_uncertainty(self):
        result=calibrate([exchange(i) for i in (1000,2000,3000)])
        self.assertLess(result['offset_lower_ms'],350)
        self.assertGreater(result['offset_upper_ms'],350)
        self.assertEqual(result['samples'],3)
        self.assertTrue(ingress_in_clock_interval(1355,1000,1012,result,monotonic=2))
        self.assertFalse(ingress_in_clock_interval(2000,1000,1012,result,monotonic=2))

    def test_clock_jump_reversed_time_and_too_few_samples_are_invalid(self):
        bad=dict(exchange(),roundtrip_ms=50)
        for rows in ([exchange()],[bad]*3,[dict(exchange(),server_sent_ms=1)]*3):
            with self.assertRaises(ValueError): calibrate(rows)

    def test_inconsistent_offset_bounds_are_not_averaged_into_success(self):
        with self.assertRaises(ValueError): calibrate([exchange(),exchange(),exchange(offset=500)])

    def test_stale_clock_is_rejected(self):
        clock=calibrate([exchange()]*3)
        self.assertFalse(ingress_in_clock_interval(1355,1000,1012,clock,monotonic=302,max_age=300))

    def test_local_100ms_check_remains_and_ec2_can_use_interval(self):
        clock=calibrate([exchange()]*3)
        args=('measurement','background',1,{'x-request-id':'a'*32,'x-dualguard-request-start':'1.355'},200,12,1000,1012)
        with self.assertRaises(ValueError): client_record(*args)
        with patch('ec2_watch.time.perf_counter',return_value=2):
            self.assertEqual(client_record(*args,clock=clock)['requestId'],'a'*32)

    def test_cpu_uses_deltas_and_linux_steal_is_separate(self):
        self.assertEqual(cpu_percent(dict(total=10,idle=5),dict(total=30,idle=10))['busy_percent'],75)
        before=dict(user=10,idle=10,iowait=0,steal=0)
        after=dict(user=20,idle=15,iowait=0,steal=5)
        self.assertEqual(cpu_percent(before,after,linux=True)['steal_percent'],25)
        self.assertIsNone(cpu_percent(None,after,linux=True))
        with self.assertRaises(ValueError): cpu_percent(dict(total=30,idle=10),dict(total=10,idle=5))


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.policy,_=load_observation_policy()
        self.guard=Ec2Guard(self.policy,stopper=Mock())
        self.assertTrue(self.guard.preflight(sample(self.policy)))
        self.guard.latest=0

    def test_start_memory_requires_two_gib_on_both_hosts(self):
        guard=Ec2Guard(self.policy)
        self.assertFalse(guard.preflight(sample(self.policy,generator_gib=1.5)))
        self.assertEqual(guard.abort['code'],'generator_start_memory')

    def test_each_host_has_its_own_continuous_low_memory_timer(self):
        for stamp in (5,10,15):
            self.guard.observe(sample(self.policy,stamp,generator_gib=.8),observed=stamp)
            self.assertIsNone(self.guard.abort)
        self.guard.observe(sample(self.policy,20,generator_gib=.8),observed=20)
        self.assertEqual(self.guard.abort['code'],'generator_low_memory')

    def test_recovery_and_invalid_sample_reset_low_memory_continuity(self):
        for stamp in (5,10): self.guard.observe(sample(self.policy,stamp,server_gib=.8),observed=stamp)
        self.guard.observe(sample(self.policy,15),observed=15)
        self.guard.observe(sample(self.policy,20,server_gib=.8),observed=20)
        self.assertIsNone(self.guard.abort)
        self.guard.observe({},observed=25)
        self.guard.observe(sample(self.policy,30,server_gib=.8),observed=30)
        self.assertIsNone(self.guard.abort)

    def test_oom_restart_replacement_and_unhealthy_are_detected(self):
        for key,value in [('oom_killed',True),('restart_count',1),('id','replacement'),('health','unhealthy'),('running',False)]:
            guard=Ec2Guard(self.policy)
            guard.preflight(sample(self.policy))
            guard.latest=0
            changed=sample(self.policy,5)
            changed['containers'][0][key]=value
            guard.observe(changed,observed=5)
            self.assertEqual(guard.abort['code'],'container_state')

    def test_healthy_sample_records_cpu_without_stopping_at_100_percent(self):
        row=sample(self.policy,5)
        self.guard.observe(row,observed=5)
        self.assertIsNone(self.guard.abort)
        self.assertIn('steal_percent',row['cpu_interval']['server'])

    def test_reboot_and_observation_stale_are_detected(self):
        row=sample(self.policy,5)
        row['server']['boot_sha256']='b'*64
        self.guard.observe(row,observed=5)
        self.assertEqual(self.guard.abort['code'],'server_reboot')
        guard=Ec2Guard(self.policy)
        guard.preflight(sample(self.policy))
        guard.latest=0
        guard.watchdog(observed=16)
        self.assertEqual(guard.abort['code'],'resource_stale')

    def test_two_invalid_samples_stop_but_do_not_claim_data_loss(self):
        self.guard.observe({},observed=5)
        self.assertIsNone(self.guard.abort)
        self.guard.observe({},observed=10)
        self.assertEqual(self.guard.abort['verdict'],'INCONCLUSIVE')

    def test_stop_only_calls_explicitly_attached_owned_process_once(self):
        process=Mock()
        process.poll.return_value=None
        self.guard.attach_owned_load(process)
        self.guard.watchdog(observed=20)
        self.guard.watchdog(observed=21)
        self.guard.stopper.assert_called_once_with(process)

    def test_provider_failure_is_not_an_empty_healthy_sample(self):
        guard=Ec2Guard(self.policy,sample_provider=Mock(side_effect=OSError('private-data')))
        guard.preflight(sample(self.policy))
        guard.resources()
        guard.resources()
        self.assertIsNotNone(guard.abort)
        self.assertNotIn('private-data',json.dumps(guard.abort))

    def test_owned_temporary_process_is_actually_stopped_without_touching_services(self):
        options=dict(stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if sys.platform=='win32': options['creationflags']=subprocess.CREATE_NO_WINDOW
        process=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],**options)
        try:
            guard=Ec2Guard(self.policy)
            guard.attach_owned_load(process)
            guard.rules.trip('test','시험용 중단','INCONCLUSIVE',{})
            guard.apply_stop()
            self.assertIsNotNone(process.poll())
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)

    def test_dry_run_does_not_open_ssh_reserve_or_sample(self):
        with patch('run_ec2_watch.reserve') as reserve,patch('run_ec2_watch.WatchSession') as session, \
                patch('run_ec2_watch.generator_snapshot') as generator,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['--dry-run']),0)
        reserve.assert_not_called()
        session.assert_not_called()
        generator.assert_not_called()


if __name__=='__main__': unittest.main()
