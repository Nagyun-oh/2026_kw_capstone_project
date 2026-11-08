import asyncio
import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, Mock, patch

from e2e_core import ClockObservationError, client_record
from run_e2e import Experiment
from run_ec2_e2e import EC2Experiment


class ClockRecheckTests(unittest.IsolatedAsyncioTestCase):
    def clock(self,lower,upper,*,age=0):
        return dict(offset_lower_ms=lower,offset_upper_ms=upper,
                    observed_monotonic=time.perf_counter()-age,
                    generator_reference_ms=1000000,
                    calibrated_at='2026-11-06T01:22:44+00:00')

    def observation(self):
        # 실제 중단 표본과 같은 약 1.5ms 상한 초과를 재현한다.
        return dict(phase='measurement',kind='background',sequence=449,
                    headers={'x-request-id':'a'*32,'x-dualguard-request-start':'998.521'},
                    status=200,duration_ms=.7607,sent_ms=1000000,ended_ms=1000001,c0=42)

    def runner(self):
        r=EC2Experiment.__new__(EC2Experiment)
        r.clock_calibration=self.clock(-1488.349,-1482.524)
        r.clock_observation_rechecks=0
        r.phase_name='measurement'
        r.manifest={}
        # 기존(개정 5 이전) 중단 동작을 검증한다. 개정 6의 진단 기록 경로는 test_ec2_load에서 따로 본다.
        r.contract={'clock_policy':{'k6_background_window_mismatch':'abort'}}
        r.check_abort=Mock()
        r.event=Mock()
        async def calibrate(label):
            fresh=self.clock(-1486.831,-1480.936)
            # 동시 표본으로 구성해 UTC/단조 시계 점프가 없게 한다.
            fresh['observed_monotonic']=r.clock_calibration['observed_monotonic']
            r.clock_calibration=fresh
        r.calibrate=AsyncMock(side_effect=calibrate)
        return r

    async def test_fresh_measured_interval_can_validate_without_tolerance_or_resend(self):
        r=self.runner()
        with self.assertRaises(ClockObservationError):
            client_record(**self.observation(),clock=r.clock_calibration)
        self.assertTrue(await r.refresh_clock_observation())
        row=client_record(**self.observation(),clock=r.clock_calibration)
        self.assertEqual(row['requestId'],'a'*32)
        self.assertEqual(row['duration_ms'],.7607)
        self.assertEqual(r.manifest['clock_rechecks'][0]['requests_resent'],0)

    async def test_still_inconsistent_observation_is_rejected(self):
        r=self.runner()
        await r.refresh_clock_observation()
        value=self.observation()
        value['headers']['x-dualguard-request-start']='1008.52'
        with self.assertRaises(ClockObservationError):
            client_record(**value,clock=r.clock_calibration)

    async def test_disjoint_calibration_is_a_discontinuity(self):
        r=self.runner()
        async def calibrate(label):
            r.clock_calibration={**r.clock_calibration,'offset_lower_ms':100,'offset_upper_ms':110}
        r.calibrate.side_effect=calibrate
        with self.assertRaisesRegex(RuntimeError,'CLOCK_RECHECK_DISCONTINUITY'):
            await r.refresh_clock_observation()

    async def test_utc_jump_is_not_hidden_by_fresh_calibration(self):
        r=self.runner()
        async def calibrate(label):
            r.clock_calibration={**r.clock_calibration,'generator_reference_ms':1001000}
        r.calibrate.side_effect=calibrate
        with self.assertRaisesRegex(RuntimeError,'CLOCK_RECHECK_DISCONTINUITY'):
            await r.refresh_clock_observation()

    async def test_coarse_display_timestamp_does_not_create_a_false_clock_jump(self):
        r=self.runner()
        async def calibrate(label):
            r.clock_calibration={**r.clock_calibration,'calibrated_at':'2026-11-06T01:22:44.014+00:00'}
        r.calibrate.side_effect=calibrate
        self.assertTrue(await r.refresh_clock_observation())

    async def test_k6_millisecond_quantization_is_bounded_and_recorded(self):
        r=self.runner()
        value=self.observation()
        value['headers']['x-dualguard-request-start']='998.519'
        row=client_record(**value,clock=r.clock_calibration,client_clock_resolution_ms=1)
        self.assertEqual(row['clock_resolution_ms'],dict(ingress=1,client=1))
        value['headers']['x-dualguard-request-start']='998.523'
        with self.assertRaises(ClockObservationError):
            client_record(**value,clock=r.clock_calibration,client_clock_resolution_ms=1)
        with self.assertRaises(ValueError):
            client_record(**value,clock=r.clock_calibration,client_clock_resolution_ms=100)

    async def test_expired_clock_and_retry_limit_still_stop(self):
        r=self.runner()
        r.clock_calibration['observed_monotonic']=time.perf_counter()-301
        self.assertFalse(await r.refresh_clock_observation())
        r.calibrate.assert_not_awaited()
        r.clock_observation_rechecks=3
        self.assertFalse(await r.refresh_clock_observation())

    async def test_old_rows_keep_their_valid_original_calibration(self):
        r=self.runner()
        old=self.observation()
        old['headers']['x-dualguard-request-start']='998.512'
        old['ended_ms']=1000010
        client_record(**old,clock=r.clock_calibration)
        await r.refresh_clock_observation()
        client_record(**old,clock=r.clock_calibration)

    async def test_probe_rechecks_the_same_response_exactly_once(self):
        r=self.runner()
        r.probe={}
        r.manifest={'id':'test-clock'}
        observation=self.observation()
        observation['kind']='probe'
        error=ClockObservationError('시각 미확인')
        error.observation=observation
        with patch('run_ec2_e2e.send_http',side_effect=error) as send:
            row=await r.send_probe('measurement',449)
        send.assert_called_once()
        self.assertEqual(row['c0'],42)
        self.assertEqual(row['ended_ms'],observation['ended_ms'])

    async def test_parser_only_retries_clock_error_and_local_behavior_is_unchanged(self):
        r=self.runner()
        with patch('run_e2e.parse_points',side_effect=[ClockObservationError('시각'),['ok']]):
            self.assertEqual(await r.read_client_points(Path('unused')),['ok'])
        r.refresh_clock_observation=AsyncMock()
        with patch('run_e2e.parse_points',side_effect=ValueError('JSON 손상')):
            with self.assertRaises(ValueError):await r.read_client_points(Path('unused'))
        r.refresh_clock_observation.assert_not_awaited()
        local=Experiment.__new__(Experiment)
        local.clock_calibration=None
        with patch('run_e2e.parse_points',side_effect=ClockObservationError('시각')):
            with self.assertRaises(ClockObservationError):await local.read_client_points(Path('unused'))
        # 개정 6 진단 경로도 시계 오류만 재보정하고 JSON 손상은 그대로 실패시킨다.
        r.contract={'clock_policy':{'k6_background_window_mismatch':'diagnostic'}}
        r.seen_clients=set()
        r.refresh_clock_observation=AsyncMock(return_value=True)
        with patch('run_ec2_e2e.parse_points',side_effect=[ClockObservationError('보정 만료'),['ok']]):
            self.assertEqual(await r.read_client_points(Path('unused')),['ok'])
        r.refresh_clock_observation=AsyncMock()
        with patch('run_ec2_e2e.parse_points',side_effect=ValueError('JSON 손상')):
            with self.assertRaises(ValueError):await r.read_client_points(Path('unused'))
        r.refresh_clock_observation.assert_not_awaited()


if __name__=='__main__':unittest.main()
