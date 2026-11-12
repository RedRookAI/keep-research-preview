"""Frozen-byte/source and actual-export regressions; no transfer or VM."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


upload = load('candidate_upload', 'upload_candidate.py')
consumer = load('candidate_consumer', 'consumer.py')


class FrozenCandidate(unittest.TestCase):
    def test_failed_host_command_retains_stderr_and_withholds_stdout(self):
        with self.assertRaisesRegex(RuntimeError, 'host-key metadata failure') as captured:
            consumer.execute([sys.executable, '-c', 'import sys;print("invitation stdout excluded");sys.stderr.write("host-key metadata failure");raise SystemExit(4)'])
        self.assertNotIn('invitation stdout excluded', str(captured.exception))

    def test_host_assembly_and_unchanged_guest_image_have_explicit_sources(self):
        original = {'source': 'a' * 40, 'components': {'source': 'a' * 40}}
        self.assertEqual(consumer.runtime_source(original), 'a' * 40)
        repacked = {**original, 'source': 'b' * 40, 'imageSource': 'a' * 40}
        consumer.verify_manifest_source(repacked, 'b' * 40)
        self.assertEqual(consumer.runtime_source(repacked), 'a' * 40)
        with self.assertRaisesRegex(RuntimeError, 'image provenance'):
            consumer.runtime_source({**repacked, 'components': {'source': 'c' * 40}})

    def test_guest_binary_capture_preserves_bytes_and_refuses_failed_command(self):
        with tempfile.TemporaryDirectory(prefix='guest evidence ') as temporary:
            root = Path(temporary)
            wanted = b'\x1f\x8b\x00\xff\n\n'
            path = root / 'support.tar.gz'
            receipt = consumer.capture_file([sys.executable, '-c', 'import sys;sys.stdout.buffer.write(bytes.fromhex("1f8b00ff0a0a"))'], path)
            self.assertEqual(path.read_bytes(), wanted)
            self.assertEqual(receipt, {'file': path.name, 'sha256': hashlib.sha256(wanted).hexdigest(), 'bytes': len(wanted)})
            with self.assertRaisesRegex(RuntimeError, 'public-support: Permission denied') as captured:
                consumer.capture_file([sys.executable, '-c', 'import sys;sys.stdout.write("binary stdout excluded");sys.stderr.write("public-support: Permission denied");raise SystemExit(4)'], root / 'failed')
            self.assertNotIn('binary stdout excluded', str(captured.exception))

    def test_postfreeze_bytes_size_descriptor_and_source_must_all_match(self):
        with tempfile.TemporaryDirectory(prefix='candidate bytes ') as temporary:
            root = Path(temporary); archive = root / 'candidate.tar.xz'; archive.write_bytes(b'frozen test transport')
            source = 'a' * 40; wanted = hashlib.sha256(archive.read_bytes()).hexdigest()
            metadata = {'archive': archive.name, 'source': source, 'sha256': wanted, 'compressedBytes': archive.stat().st_size}
            (root / 'SHA256SUMS').write_text(wanted + '  ' + archive.name + '\n')
            self.assertEqual(upload.verify_frozen_candidate(root, metadata, source), archive)
            for changed in [dict(metadata, compressedBytes=1), dict(metadata, source='b' * 40), dict(metadata, sha256='c' * 64)]:
                with self.assertRaises(RuntimeError): upload.verify_frozen_candidate(root, changed, source)
            archive.write_bytes(b'mutated after receipt')
            with self.assertRaisesRegex(RuntimeError, 'hash or size changed'):
                upload.verify_frozen_candidate(root, metadata, source)
            archive.write_bytes(b'frozen test transport')
            (root / 'SHA256SUMS').write_text('a different descriptor\n')
            with self.assertRaisesRegex(RuntimeError, 'checksum descriptor'):
                upload.verify_frozen_candidate(root, metadata, source)

    def test_consumer_requires_independent_frozen_source(self):
        consumer.verify_manifest_source({'source': 'a' * 40}, 'a' * 40)
        for expected in [None, '', 'b' * 40]:
            with self.assertRaisesRegex(RuntimeError, 'independently supplied'):
                consumer.verify_manifest_source({'source': 'a' * 40}, expected)


class ActualPortableExport(unittest.TestCase):
    def setUp(self):
        # Actual HTTPS controlled-sample browser download, November12. This is
        # historical arithmetic evidence for the unchanged export schema only.
        self.value = json.loads((Path(__file__).parent / 'test-data/actual-proposal.json').read_text())
        self.data = self.value['data']

    def verify(self, value, **changes):
        args = {'project_id': self.data['projectId'], 'run_id': self.data['runId'], 'decision': 'veto',
                'digest': self.data['proposal']['patchSha256'], 'expected_tests': self.data['proposal']['checks']['passedTests']}
        args.update(changes)
        return consumer.verify_export(value, **args)

    def test_actual_download_uses_complete_canonical_body(self):
        self.assertEqual(self.verify(self.value), self.data)
        changed = copy.deepcopy(self.value); changed['data']['proposal']['diff'] += '\n'
        with self.assertRaisesRegex(RuntimeError, 'checksum'): self.verify(changed)

    def test_another_project_or_unrelated_approval_does_not_count(self):
        with self.assertRaisesRegex(RuntimeError, 'another project'):
            self.verify(self.value, project_id='another-project')
        with self.assertRaisesRegex(RuntimeError, 'Exact human proposal decision'):
            self.verify(self.value, decision='approve')
        changed = copy.deepcopy(self.value)
        human = next(item for item in changed['data']['decisions'] if item['event'] == 'project.human-proposal-decision')
        human['proposalDigest'] = 'd' * 64
        body = {key: changed[key] for key in ('schema', 'assurance', 'data')}
        changed['sha256'] = hashlib.sha256(json.dumps(body, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode()).hexdigest()
        with self.assertRaisesRegex(RuntimeError, 'Exact human proposal decision'): self.verify(changed)


if __name__ == '__main__': unittest.main()
