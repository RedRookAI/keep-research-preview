"""Exact source-file transfer admission; no network or cloud mutation."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import test_source_companion as fixture

spec = importlib.util.spec_from_file_location('source_upload', Path(__file__).with_name('upload_source_companion.py'))
upload = importlib.util.module_from_spec(spec); spec.loader.exec_module(upload)


class SourceUpload(unittest.TestCase):
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
