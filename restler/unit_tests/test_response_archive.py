# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import copy
import gc
import json
import os
from pathlib import Path
import stat
import tempfile
import tracemalloc
import unittest
from unittest.mock import patch

from restler_settings import RestlerSettings
from engine.core import sequences, requests, request_utilities
from engine.core.fuzzing_monitor import FuzzingMonitor
from engine import primitives
from engine.transport_layer.response import HttpResponse
import utils.logger as logger


class ResponseArchiveTest(unittest.TestCase):
    def setUp(self):
        for cls, attribute in [(RestlerSettings, '_RestlerSettings__instance'),
                               (FuzzingMonitor, '_FuzzingMonitor__instance'),
                               (requests.GlobalRequestCollection, '_GlobalRequestCollection__instance')]:
            instance = patch.object(cls, attribute, None)
            instance.start()
            self.addCleanup(instance.stop)
        RestlerSettings({'fuzzing_mode': 'bfs-cheap', 'max_combinations': 10, 'disable_logging': True})
        FuzzingMonitor().set_time_budget(1)
        self.collection = requests.RequestCollection()
        requests.GlobalRequestCollection(self.collection)
        self.temp = tempfile.TemporaryDirectory(prefix='restler-archive-test-')
        self.addCleanup(self.temp.cleanup)
        self.log_patch = patch.object(logger, 'LOGS_DIR', self.temp.name)
        self.log_patch.start()
        self.addCleanup(self.log_patch.stop)

    def record(self, text):
        return sequences.SentRequestData('fixture', 'GET /fixture HTTP/1.1\r\n\r\n', None, text)

    def test_full_roundtrip_deepcopy_unicode_and_permissions(self):
        text = 'HTTP/1.1 500 Error\r\nX-Test: exact\r\n\r\n' + ('Ж🙂\r\n' * 50000)
        record = self.record(text)
        self.assertFalse(any(v is text for v in record.__dict__.values()), 'Large response retained inline')
        filename = Path(record._response_file)
        self.assertEqual(filename.parent.parent, Path(self.temp.name))
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE(filename.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(filename.parent.stat().st_mode), 0o700)
        clone = copy.deepcopy(record)
        self.assertEqual(clone._response_file, str(filename))
        for item in [record, clone]:
            self.assertEqual(item.response, text)
            self.assertFalse(any(v is text for v in item.__dict__.values()), 'Getter cached large response')
        self.assertEqual(len(list(filename.parent.glob('*.gz'))), 1)

    def test_small_empty_and_none_keep_public_contract(self):
        for text in ['', None, 'HTTP/1.1 200 OK\r\n\r\n{}']:
            record = self.record(text)
            self.assertEqual(record.response, text)
            self.assertFalse(getattr(record, '_response_file', None))

    def test_native_render_parser_and_replay_see_full_body(self):
        text = json.dumps({'ID': 'fixture-id', 'payload': 'Ж' * 200000}, ensure_ascii=False)
        parsed = []
        def parser(data, **kwargs):
            obj = json.loads(data)
            self.assertEqual(obj['payload'], 'Ж' * 200000)
            parsed.append(obj['ID'])
        request = requests.Request([
            primitives.restler_static_string('GET /fixture HTTP/1.1\r\nHost: fixture\r\n\r\n'),
            {'post_send': {'parser': parser}},
        ], requestId='/fixture')
        response = HttpResponse('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n' + text)
        with patch.object(request_utilities, 'send_request_data', return_value=response), \
             patch.object(sequences, 'CUSTOM_LOGGING'), patch.object(sequences, 'RAW_LOGGING'):
            rendered = sequences.Sequence([request]).render(self.collection.candidate_values_pool, None)
            self.assertTrue(rendered.valid)
            self.assertEqual(rendered.final_request_response.body, text)
            self.assertEqual(rendered.sequence.sent_request_data_list[0].response, response.to_str)
            self.assertEqual(rendered.sequence.replay_sequence(), '200')
        self.assertGreaterEqual(len(parsed), 2)

    def test_bug_json_and_replay_reports_preserve_full_response(self):
        from engine.bug_bucketing import BugBucket
        body = 'HTTP/1.1 500 Error\r\nContent-Type: text/plain\r\n\r\n' + 'Ж' * 100000
        request = requests.Request([primitives.restler_static_string('GET /fixture HTTP/1.1\r\n\r\n')], requestId='/fixture')
        sequence = sequences.Sequence([request])
        sequence.append_data_to_sent_list(request.method_endpoint_hex_definition,
                                          'GET /fixture HTTP/1.1\r\n\r\n', None, HttpResponse(body))
        bucket = BugBucket(sequence, False, 0, 0, 'main_driver', '500')
        folder = Path(self.temp.name) / 'bugs'
        with patch.object(logger, 'BUG_BUCKETS_DIR', str(folder)), \
             patch.object(logger, 'BUG_BUCKET_LOGS', str(folder / 'bug_buckets.txt')), \
             patch.object(logger, 'Bugs_Logged', {}), patch.object(logger, 'Bug_Hashes', {}):
            logger.update_bug_buckets({'main_driver_500': {'fixture': bucket}},
                                      sequence.sent_request_data_list, 'fixture-hash')
        report = json.loads((folder / 'main_driver_500_1.json').read_text())
        self.assertEqual(report['request_sequence'][0]['response'], body)
        replay = (folder / 'main_driver_500_1.replay.txt').read_text()
        self.assertIn('PREVIOUS RESPONSE: ' + repr(body), replay)
        self.assertNotIn(body, sequence.sent_request_data_list[0].__dict__.values())

    def test_many_live_records_bound_heap_and_restore_exact_bodies(self):
        tracemalloc.start()
        self.addCleanup(tracemalloc.stop)
        records = []
        for i in range(40):
            records.append(self.record('HTTP/1.1 200 OK\r\n\r\n' + str(i) + ':' + 'Ж' * 262144))
        gc.collect()
        current = tracemalloc.get_traced_memory()[0]
        self.assertLess(current, 2 * 1024 * 1024)
        self.assertEqual(records[0].response, 'HTTP/1.1 200 OK\r\n\r\n0:' + 'Ж' * 262144)
        self.assertEqual(records[-1].response, 'HTTP/1.1 200 OK\r\n\r\n39:' + 'Ж' * 262144)

    def test_disk_failure_is_explicit_and_partial_file_removed(self):
        record = self.record('old')
        with patch('engine.core.sequences.gzip.GzipFile', side_effect=OSError('fixture disk full')):
            with self.assertRaisesRegex(OSError, 'fixture disk full'):
                record.response = 'Ж' * 100000
        self.assertEqual(record.response, 'old')
        self.assertEqual(list(Path(self.temp.name).rglob('*.gz')), [])
