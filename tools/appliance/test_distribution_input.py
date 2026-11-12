"""Consumer evidence custody checks; no network, VM, accounts or source download."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('distribution_input', Path(__file__).with_name('fetch_distribution_input.py'))
fetch = importlib.util.module_from_spec(spec); spec.loader.exec_module(fetch)


class DistributionCustody(unittest.TestCase):
    def fixture(self):
        files = {'guest-dpkg-status': b'Package: fixture\nStatus: install ok installed\n',
                 'guest-packages.tsv': b'fixture\t1\tfixture\t1\n', 'guest-distribution-support.tar.gz': b'compressed fixture\x00\xff\n'}
        receipt = {'schema': 'keep.appliance.distribution-input/v1', 'source': 'a' * 40, 'imageSha256': 'b' * 64,
            'files': [{'file': n, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)} for n, data in files.items()]}
        consumer = {'schema': 'keep.appliance.clean-consumer/v1', 'source': receipt['source'], 'imageSha256': receipt['imageSha256'], 'passed': True, 'paidCalls': 0}
        files.update({'distribution-input.json': json.dumps(receipt).encode(), 'consumer.json': json.dumps(consumer).encode()})
        return files

    def archive(self, files):
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as stream:
            for n, value in files.items(): stream.writestr(n, value)
        return data.getvalue()

    def test_exact_healthy_import_and_changed_guest_bytes_or_identity(self):
        files = self.fixture()
        with tempfile.TemporaryDirectory(prefix='distribution custody ') as temporary:
            output = Path(temporary) / 'exact input'
            fetch.unpack(self.archive(files), output)
            fetch.verify(output, 'a' * 40, 'b' * 64)
            with self.assertRaisesRegex(RuntimeError, 'identity'):
                fetch.verify(output, 'c' * 40, 'b' * 64)
            (output / 'guest-dpkg-status').write_bytes(b'changed inventory')
            with self.assertRaisesRegex(RuntimeError, 'bytes differ'):
                fetch.verify(output, 'a' * 40, 'b' * 64)

    def test_failed_consumer_and_missing_evidence_are_refused(self):
        files = self.fixture()
        consumer = json.loads(files['consumer.json']); consumer['passed'] = False
        files['consumer.json'] = json.dumps(consumer).encode()
        with tempfile.TemporaryDirectory(prefix='distribution refusal ') as temporary:
            output = Path(temporary) / 'failed'; fetch.unpack(self.archive(files), output)
            with self.assertRaisesRegex(RuntimeError, 'did not pass'):
                fetch.verify(output, 'a' * 40, 'b' * 64)
            del files['guest-dpkg-status']
            with self.assertRaisesRegex(RuntimeError, 'lacks final'):
                fetch.unpack(self.archive(files), Path(temporary) / 'incomplete')
            self.assertFalse((Path(temporary) / 'incomplete').exists())


if __name__ == '__main__': unittest.main()
