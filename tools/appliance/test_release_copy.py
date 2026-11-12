"""Small synthetic draft custody checks. No network, platform token or archive extraction."""
import copy
import importlib.util
import json
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('release_copy', Path(__file__).with_name('copy_release_assets.py'))
app = importlib.util.module_from_spec(spec); spec.loader.exec_module(app)


def fixture():
    payloads = {name: ('synthetic ' + name).encode() for name in app.SOURCE_FILES}
    payloads.update({'debian-sources-0001.tar': b'opaque source archive; never extracted',
                     'qualified.tar.xz': b'opaque qualified appliance; never extracted',
                     'actual-qualification.json': b'{"syntheticTestOnly":true,"actualResultIsNotClaimed":true}',
                     'qualified.tar.xz.candidate.json': b'{"consumerPassed":false}'})
    part = payloads['debian-sources-0001.tar']
    index = {'schema': 'keep.appliance.debian-source-companion/v1', 'source': 'a' * 40,
             'imageSha256': 'b' * 64, 'complete': True, 'planOnly': False, 'missing': [],
             'assets': [{'file': 'debian-sources-0001.tar', 'sha256': app.sha256(part), 'bytes': len(part)}]}
    payloads['source-index.json'] = json.dumps(index).encode()
    source_names = app.SOURCE_FILES | {'debian-sources-0001.tar'}
    payloads['SHA256SUMS'] = ''.join(app.sha256(payloads[n]) + '  ' + n + '\n' for n in sorted(source_names)).encode()
    payloads['qualified.tar.xz.sha256'] = (app.sha256(payloads['qualified.tar.xz']) + '  qualified.tar.xz\n').encode()
    assets = [{'id': n, 'name': name, 'sha256': app.sha256(body), 'bytes': len(body)}
              for n, (name, body) in enumerate(payloads.items(), start=1)]
    plan = {'schema': 'keep.appliance.release-copy/v1', 'ready': True, 'repository': app.REPOSITORY,
            'sourceRelease': {'id': app.SOURCE_RELEASE_ID, 'tag': 'old-private-draft', 'target': 'c' * 40},
            'destinationRelease': {'id': 123, 'tag': 'new-private-draft', 'target': 'd' * 40},
            'archive': 'qualified.tar.xz', 'imageSource': 'a' * 40, 'imageSha256': 'b' * 64,
            'qualification': {'receiptAsset': 'actual-qualification.json', 'runId': 11,
                              'workflowSource': 'e' * 40, 'artifactId': 12, 'artifactSha256': 'f' * 64},
            'assets': assets}
    return plan, payloads


def metadata(asset):
    return {'id': asset['id'], 'name': asset['name'], 'size': asset['bytes'], 'digest': 'sha256:' + asset['sha256']}


class FakeGitHub:
    def __init__(self, plan, payloads):
        self.plan, self.payloads = plan, dict(payloads)
        self.sources = [metadata(a) for a in plan['assets']]
        self.sources.append({'id': 999, 'name': 'old-bad.tar.xz', 'size': 3, 'digest': 'sha256:' + '0' * 64})
        self.destination, self.uploads, self.calls = [], [], []
        self.corrupt_download, self.unknown_upload, self.wrong_readback = None, False, False
        self.source_changes = {}

    def release(self, release_id):
        self.calls.append(('release', release_id))
        source = release_id == app.SOURCE_RELEASE_ID
        expected = self.plan['sourceRelease' if source else 'destinationRelease']
        result = {'id': expected['id'], 'tag_name': expected['tag'], 'target_commitish': expected['target'],
                  'draft': True, 'assets': copy.deepcopy(self.sources if source else self.destination)}
        if source: result.update(self.source_changes)
        return result

    def download(self, asset_id, output, expected_bytes):
        self.calls.append(('download', asset_id))
        name = next(a['name'] for a in self.sources if a['id'] == asset_id)
        output.write_bytes(b'wrong bytes' if name == self.corrupt_download else self.payloads[name])

    def upload(self, release_id, wanted, path):
        self.calls.append(('upload', release_id, wanted['name']))
        assert release_id == self.plan['destinationRelease']['id']
        body = path.read_bytes()
        assert len(body) == wanted['bytes'] and app.sha256(body) == wanted['sha256']
        assert wanted['name'] not in {a['name'] for a in self.destination}
        actual = metadata({**wanted, 'id': 1000 + len(self.destination)})
        self.destination.append(actual)
        self.uploads.append((wanted['name'], body))
        if self.unknown_upload: raise OSError('synthetic lost upload response')
        return copy.deepcopy(actual)

    def asset(self, asset_id):
        self.calls.append(('asset', asset_id))
        result = copy.deepcopy(next(a for a in self.destination if a['id'] == asset_id))
        if self.wrong_readback: result['digest'] = 'sha256:' + '0' * 64
        return result


class ReleaseCopy(unittest.TestCase):
    def run_copy(self, plan, provider, events):
        with tempfile.TemporaryDirectory(prefix='release copy fixture ') as temporary:
            return app.copy_assets(plan, provider, Path(temporary), events.append)

    def test_exact_selection_complete_sources_and_collision_free_combined_checksums(self):
        plan, payloads = fixture(); provider = FakeGitHub(plan, payloads); events = []
        original_source = copy.deepcopy(provider.sources)
        result = self.run_copy(plan, provider, events)
        copied = dict(provider.uploads)
        self.assertEqual(set(copied), set(payloads) | {app.CHECKSUM_NAME})
        self.assertNotIn('old-bad.tar.xz', copied)
        self.assertEqual(provider.sources, original_source)
        self.assertEqual(copied['qualified.tar.xz.candidate.json'], b'{"consumerPassed":false}')
        self.assertEqual(copied['SHA256SUMS'], payloads['SHA256SUMS'])
        self.assertEqual(copied['qualified.tar.xz.sha256'], payloads['qualified.tar.xz.sha256'])
        expected = ''.join(app.sha256(body) + '  ' + name + '\n' for name, body in sorted(payloads.items())).encode()
        self.assertEqual(copied[app.CHECKSUM_NAME], expected)
        self.assertEqual(result['state'], 'complete'); self.assertTrue(result['draft'])
        for selected in plan['assets']:
            self.assertEqual(result['assets'][selected['name']]['sourceAssetId'], selected['id'])
        for name, _ in provider.uploads:
            intent = next(i for i, e in enumerate(events) if e['state'] == 'upload-intent' and e['name'] == name)
            confirmed = next(i for i, e in enumerate(events) if e['state'] == 'upload-confirmed' and e['name'] == name)
            self.assertLess(intent, confirmed)
        self.assertEqual(provider.calls[-1], ('release', app.SOURCE_RELEASE_ID))
        self.assertIn(('release', plan['destinationRelease']['id']), provider.calls[-2:])

    def test_unready_wrong_draft_and_wrong_source_asset_refuse_without_writes(self):
        for case in ('unready', 'published', 'wrong target', 'wrong asset id', 'wrong source digest'):
            with self.subTest(case=case):
                plan, payloads = fixture(); provider = FakeGitHub(plan, payloads)
                if case == 'unready': plan['ready'] = False
                if case == 'published': provider.source_changes['draft'] = False
                if case == 'wrong target': provider.source_changes['target_commitish'] = '0' * 40
                if case == 'wrong asset id': plan['assets'][-1]['id'] = 1111
                if case == 'wrong source digest': provider.sources[-2]['digest'] = 'sha256:' + '0' * 64
                with self.assertRaises(RuntimeError): self.run_copy(plan, provider, [])
                self.assertEqual(provider.uploads, [])
                if case == 'unready': self.assertEqual(provider.calls, [])

    def test_late_destination_conflict_or_unselected_asset_precedes_all_writes(self):
        for case in ('last selected conflict', 'combined checksum conflict', 'unselected existing'):
            with self.subTest(case=case):
                plan, payloads = fixture(); provider = FakeGitHub(plan, payloads)
                wanted = plan['assets'][-1]
                conflict = metadata({**wanted, 'id': 700})
                if case == 'combined checksum conflict': conflict['name'] = app.CHECKSUM_NAME
                if case == 'unselected existing': conflict['name'] = 'other.tar.xz'
                conflict['digest'] = 'sha256:' + '0' * 64
                provider.destination.append(conflict)
                with self.assertRaises(RuntimeError): self.run_copy(plan, provider, [])
                self.assertEqual(provider.uploads, [])
                self.assertFalse(any(c[0] == 'download' for c in provider.calls))

    def test_missing_source_part_and_corrupt_download_never_upload(self):
        for case in ('missing source part', 'download changed', 'wrong image source'):
            with self.subTest(case=case):
                plan, payloads = fixture(); provider = FakeGitHub(plan, payloads)
                if case == 'missing source part':
                    plan['assets'] = [a for a in plan['assets'] if a['name'] != 'debian-sources-0001.tar']
                elif case == 'download changed':
                    provider.corrupt_download = 'source-index.json'
                else:
                    plan['imageSource'] = '0' * 40
                with self.assertRaises(RuntimeError): self.run_copy(plan, provider, [])
                self.assertEqual(provider.uploads, [])

    def test_exact_existing_asset_is_reused_without_overwrite(self):
        plan, payloads = fixture(); provider = FakeGitHub(plan, payloads)
        provider.destination.append(metadata({**plan['assets'][0], 'id': 700}))
        result = self.run_copy(plan, provider, [])
        self.assertEqual(result['assets'][plan['assets'][0]['name']]['id'], 700)
        self.assertNotIn(plan['assets'][0]['name'], {name for name, _ in provider.uploads})

    def test_final_api_readback_change_refuses_completion(self):
        plan, payloads = fixture(); provider = FakeGitHub(plan, payloads); events = []
        original_release = provider.release

        def release(release_id):
            result = original_release(release_id)
            if release_id == plan['destinationRelease']['id'] and len(provider.destination) == len(plan['assets']) + 1:
                result['assets'][-1]['digest'] = 'sha256:' + '0' * 64
            return result

        provider.release = release
        with self.assertRaisesRegex(RuntimeError, 'Asset identity differs'):
            self.run_copy(plan, provider, events)
        self.assertEqual(len(provider.uploads), len(plan['assets']) + 1)
        self.assertFalse(any(e['state'] == 'complete' for e in events))

    def test_download_token_is_not_redirectable_and_size_overrun_refuses(self):
        provider = app.GitHub('synthetic-token')
        with patch.object(app.urllib.request, 'urlopen', return_value=io.BytesIO(b'oversized')) as request:
            with tempfile.TemporaryDirectory(prefix='bounded copy ') as temporary:
                with self.assertRaisesRegex(RuntimeError, 'exceeds frozen asset size'):
                    provider.download(1, Path(temporary) / 'asset', 2)
            actual = request.call_args.args[0]
            self.assertEqual(actual.full_url, 'https://api.github.com/repos/' + app.REPOSITORY + '/releases/assets/1')
            self.assertEqual(actual.unredirected_hdrs['Authorization'], 'Bearer synthetic-token')
            self.assertNotIn('Authorization', actual.headers)

    def test_unknown_upload_or_wrong_readback_stops_without_retry_or_completion(self):
        for case in ('unknown_upload', 'wrong_readback'):
            with self.subTest(case=case):
                plan, payloads = fixture(); provider = FakeGitHub(plan, payloads); events = []
                setattr(provider, case, True)
                with self.assertRaisesRegex(RuntimeError, 'unconfirmed.*inspect exact draft'):
                    self.run_copy(plan, provider, events)
                self.assertEqual(len(provider.uploads), 1)
                self.assertEqual(events[-1]['state'], 'upload-unconfirmed')
                self.assertTrue(any(e['state'] == 'upload-intent' for e in events))
                self.assertFalse(any(e['state'] == 'complete' for e in events))


if __name__ == '__main__': unittest.main()
