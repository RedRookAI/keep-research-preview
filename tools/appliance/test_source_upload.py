"""Exact source-file transfer admission; no network or cloud mutation."""
import importlib.util
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import test_source_companion as fixture

spec = importlib.util.spec_from_file_location('source_upload', Path(__file__).with_name('upload_source_companion.py'))
upload = importlib.util.module_from_spec(spec); spec.loader.exec_module(upload)


class SourceUpload(unittest.TestCase):
    def qualification_fixture(self, root):
        directory = root / 'distribution-input'; directory.mkdir()
        consumer = {'schema': 'keep.appliance.clean-consumer/v1', 'source': 'a' * 40, 'imageSha256': 'b' * 64, 'passed': True, 'paidCalls': 0}
        custody = {'schema': 'keep.appliance.distribution-custody/v1', 'source': 'a' * 40, 'imageSha256': 'b' * 64, 'purpose': 'qualified-consumer', 'consumerQualified': True}
        (directory / 'consumer.json').write_bytes((json.dumps(consumer, indent=3) + '\n\n').encode())
        (directory / 'custody.json').write_text(json.dumps(custody))
        return directory, consumer, custody

    def test_qualified_consumer_bytes_are_separate_from_unchanged_source_checksums(self):
        with tempfile.TemporaryDirectory(prefix='consumer qualification ') as temporary:
            root = Path(temporary); directory, _, _ = self.qualification_fixture(root)
            output = root / 'source-output'; output.mkdir(); self.fixture(output)
            source_checksums = (output / 'SHA256SUMS').read_bytes()
            upload.verified_files(output, 'a' * 40, 'b' * 64)
            record = upload.consumer_qualification(directory, output, 'a' * 40, 'b' * 64, 'qualified-consumer')
            original = (directory / 'consumer.json').read_bytes()
            self.assertEqual((output / 'consumer-qualification.json').read_bytes(), original)
            self.assertEqual(record, {'sha256': hashlib.sha256(original).hexdigest(), 'bytes': len(original)})
            self.assertEqual((output / 'SHA256SUMS').read_bytes(), source_checksums)
            self.assertNotIn('consumer-qualification.json', upload.verified_files(output, 'a' * 40, 'b' * 64))

    def test_failed_mismatched_or_unqualified_custody_never_creates_qualification(self):
        with tempfile.TemporaryDirectory(prefix='consumer refusal ') as temporary:
            root = Path(temporary); directory, consumer, custody = self.qualification_fixture(root)
            output = root / 'output'; output.mkdir()
            cases = [('consumer', 'passed', False), ('consumer', 'source', 'c' * 40), ('consumer', 'imageSha256', 'c' * 64),
                     ('consumer', 'paidCalls', 1), ('consumer', 'paidCalls', False), ('custody', 'consumerQualified', False),
                     ('custody', 'purpose', 'captured-distribution'), ('custody', 'source', 'c' * 40), ('custody', 'imageSha256', 'c' * 64)]
            for target, key, value in cases:
                with self.subTest(target=target, key=key, value=value):
                    changed_consumer, changed_custody = copy.deepcopy(consumer), copy.deepcopy(custody)
                    (changed_consumer if target == 'consumer' else changed_custody)[key] = value
                    (directory / 'consumer.json').write_text(json.dumps(changed_consumer)); (directory / 'custody.json').write_text(json.dumps(changed_custody))
                    with self.assertRaises(RuntimeError): upload.consumer_qualification(directory, output, 'a' * 40, 'b' * 64, 'qualified-consumer')
                    self.assertFalse((output / 'consumer-qualification.json').exists())

    def test_source_only_capture_cannot_export_even_a_stale_passing_consumer(self):
        with tempfile.TemporaryDirectory(prefix='source-only qualification ') as temporary:
            root = Path(temporary); directory, _, _ = self.qualification_fixture(root)
            output = root / 'output'; output.mkdir()
            self.assertIsNone(upload.consumer_qualification(directory, output, 'a' * 40, 'b' * 64, 'captured-distribution'))
            self.assertFalse((output / 'consumer-qualification.json').exists())
            with self.assertRaises(RuntimeError): upload.consumer_qualification(directory, output, 'a' * 40, 'b' * 64, 'typo')

    def test_existing_conflicting_qualification_blocks_all_release_uploads(self):
        with tempfile.TemporaryDirectory(prefix='qualification conflict ') as temporary:
            root = Path(temporary); self.qualification_fixture(root)
            output = root / 'source-output'; output.mkdir(); self.fixture(output)
            release = {'id': 10, 'tag_name': 'owned-draft', 'draft': True, 'target_commitish': 'c' * 40,
                       'assets': [{'name': 'consumer-qualification.json', 'digest': 'sha256:' + '0' * 64, 'size': 1}]}
            environment = {'GITHUB_ACTIONS': 'true', 'KC111_EXPECTED_SOURCE': 'a' * 40, 'KC111_IMAGE_SHA256': 'b' * 64,
                           'KC111_DRAFT_RELEASE_ID': '10', 'KC111_DRAFT_RELEASE_TAG': 'owned-draft', 'KC111_DRAFT_TARGET_SOURCE': 'c' * 40,
                           'KC111_CAPTURE_PURPOSE': 'qualified-consumer'}
            with contextlib.chdir(root), patch.dict(os.environ, environment), patch.object(upload, 'api', return_value=release), \
                 patch.object(upload.subprocess, 'run') as transfer, self.assertRaisesRegex(RuntimeError, 'no overwrite'):
                upload.main()
            transfer.assert_not_called()

    def test_release_target_uses_assembly_identity_separately_from_guest_sources(self):
        release = {'id': 10, 'tag_name': 'owned-draft', 'draft': True, 'target_commitish': 'c' * 40}
        upload.verify_destination(release, 10, 'owned-draft', 'c' * 40)
        for target in ['a' * 40, '']:
            with self.assertRaises(RuntimeError): upload.verify_destination(release, 10, 'owned-draft', target)
        with self.assertRaises(RuntimeError): upload.verify_destination(dict(release, draft=False), 10, 'owned-draft', 'c' * 40)

    def test_actual_companion_output_is_accepted_without_adapting_its_manifest(self):
        with tempfile.TemporaryDirectory(prefix='source integration ') as temporary, fixture.FixtureServer() as server:
            root = Path(temporary); directory, _ = fixture.input_fixture(root)
            server.source()
            output = root / 'source-output'
            index = fixture.app.build(directory, output, fixture.SOURCE, fixture.IMAGE, transport=server.transport)
            self.assertTrue(index['complete'])
            files = upload.verified_files(output, fixture.SOURCE, fixture.IMAGE)
            self.assertIn('guest-distribution-support.tar.gz', files)
            self.assertIn(index['assets'][0]['file'], files)

    def fixture(self, output):
        for name in ['distribution-input.json', 'guest-dpkg-status', 'guest-packages.tsv', 'guest-distribution-support.tar.gz', 'debian-sources-0001.tar']:
            (output / name).write_bytes(('fixture ' + name).encode())
        part = output / 'debian-sources-0001.tar'
        index = {'schema': 'keep.appliance.debian-source-companion/v1', 'source': 'a' * 40, 'imageSha256': 'b' * 64,
            'complete': True, 'planOnly': False, 'missing': [], 'assets': [{'file': part.name, 'sha256': upload.digest(part), 'bytes': part.stat().st_size}]}
        self.write_index(output, index)
        return index

    def write_index(self, output, index):
        (output / 'source-index.json').write_text(json.dumps(index))
        names = ['source-index.json', 'distribution-input.json', 'guest-dpkg-status', 'guest-packages.tsv', 'guest-distribution-support.tar.gz'] + [a['file'] for a in index['assets']]
        (output / 'SHA256SUMS').write_text(''.join(upload.digest(output / n) + '  ' + n + '\n' for n in names))

    def test_healthy_source_set_and_postfreeze_tampering(self):
        with tempfile.TemporaryDirectory(prefix='source transfer ') as temporary:
            output = Path(temporary); self.fixture(output)
            self.assertEqual(len(upload.verified_files(output, 'a' * 40, 'b' * 64)), 6)
            (output / 'debian-sources-0001.tar').write_bytes(b'changed after freeze')
            with self.assertRaisesRegex(RuntimeError, 'checksum list'):
                upload.verified_files(output, 'a' * 40, 'b' * 64)

    def test_other_image_and_explicit_gap_never_admit_transfer(self):
        with tempfile.TemporaryDirectory(prefix='source refusal ') as temporary:
            output = Path(temporary); index = self.fixture(output)
            with self.assertRaisesRegex(RuntimeError, 'another image'):
                upload.verified_files(output, 'a' * 40, 'c' * 64)
            index['missing'] = [{'package': 'fixture', 'version': '1'}]
            self.write_index(output, index)
            with self.assertRaisesRegex(RuntimeError, 'incomplete'):
                upload.verified_files(output, 'a' * 40, 'b' * 64)


if __name__ == '__main__': unittest.main()
