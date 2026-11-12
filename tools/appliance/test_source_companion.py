"""Synthetic exact-source metadata/HTTP fixtures only; no Debian source downloads."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

spec = importlib.util.spec_from_file_location('source_companion', Path(__file__).with_name('source_companion.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

SOURCE, IMAGE = 'a' * 40, 'b' * 64


def h(value, algorithm='sha256'):
    return hashlib.new(algorithm, value).hexdigest()


def status(package='hello-bin', version='1:2.0-3+b1', source='hello-src (1:2.0-3)', extra=''):
    return f'Package: {package}\nStatus: install ok installed\nArchitecture: amd64\nVersion: {version}\nSource: {source}\n{extra}Description: synthetic package\n a continuation\n .\n next paragraph\n\n'


def input_fixture(root, status_text=None, inventory=None):
    directory = root / 'consumer'
    directory.mkdir()
    values = {'guest-dpkg-status': (status_text or status()).encode(),
              'guest-packages.tsv': (inventory or 'hello-bin:amd64\t1:2.0-3+b1\thello-src\t1:2.0-3\n').encode(),
              'guest-distribution-support.tar.gz': b'synthetic separate notices only'}
    for name, value in values.items():
        (directory / name).write_bytes(value)
    receipt = {'schema': 'keep.appliance.distribution-input/v1', 'source': SOURCE, 'imageSha256': IMAGE,
               'files': [{'file': name, 'sha256': h(value), 'bytes': len(value)} for name, value in values.items()]}
    (directory / 'distribution-input.json').write_bytes(app.json_bytes(receipt))
    return directory, receipt


class FixtureServer:
    def __init__(self):
        self.routes, self.requests = {}, []
        self.server = None

    def source(self, package='hello-src', version='1:2.0-3', corrupt=False, signed=True, member_name=None):
        base = package + '_' + version.split(':')[-1]
        payloads = {member_name or base + '.orig.tar.xz': b'synthetic upstream\x00data', base + '.debian.tar.xz': b'synthetic Debian build/patch data'}
        table = ''.join(' ' + h(value) + ' ' + str(len(value)) + ' ' + name + '\n' for name, value in payloads.items())
        dsc = ('Format: 3.0 (quilt)\nSource: ' + package + '\nVersion: ' + version + '\nChecksums-Sha256:\n' + table).encode()
        if signed:
            dsc = b'-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n' + dsc + b'\n-----BEGIN PGP SIGNATURE-----\nsynthetic-not-a-real-signature\n-----END PGP SIGNATURE-----\n'
        files = dict(payloads, **{base + '.dsc': dsc})
        fileinfo, result = {}, []
        for name, value in files.items():
            digest = h(value, 'sha1')
            self.routes['/file/' + digest] = value + b'bad' if corrupt and not name.endswith('.dsc') else value
            result.append({'hash': digest})
            fileinfo[digest] = [{'name': name, 'size': len(value), 'archive_name': 'debian', 'path': '/synthetic', 'first_seen': '20261112T000000Z'}]
        path = '/mr/package/' + urllib.parse.quote(package, safe='') + '/' + urllib.parse.quote(version, safe='') + '/srcfiles?fileinfo=1'
        self.routes[path] = json.dumps({'package': package, 'version': version, 'result': result, 'fileinfo': fileinfo}).encode()
        return path, files

    def __enter__(self):
        fixture = self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                fixture.requests.append(self.path)
                data = fixture.routes.get(self.path)
                self.send_response(404 if data is None else 200)
                self.end_headers()
                if data is not None:
                    self.wfile.write(data)
            def log_message(self, *_):
                pass
        self.server = HTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def transport(self, request, timeout):
        # Production URL validation still runs; only this test seam maps to an
        # owned loopback fixture. CLI has no endpoint/HTTP bypass option.
        app.official_url(request.full_url)
        parsed = urllib.parse.urlsplit(request.full_url)
        return urllib.request.urlopen('http://127.0.0.1:' + str(self.server.server_port) + parsed.path + ('?' + parsed.query if parsed.query else ''), timeout=timeout)

    def __exit__(self, *_):
        self.server.shutdown(); self.server.server_close(); self.thread.join()


class ConsumerBinding(unittest.TestCase):
    def test_actual_receipt_shape_hashes_and_independent_source_image_are_required(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); directory, receipt = input_fixture(root)
            self.assertEqual(app.verify_input(directory, SOURCE, IMAGE), receipt)
            for source, image in [('', IMAGE), ('c' * 40, IMAGE), (SOURCE, 'c' * 64)]:
                with self.assertRaises(app.SourceError): app.verify_input(directory, source, image)
            (directory / 'guest-packages.tsv').write_bytes(b'changed')
            with self.assertRaisesRegex(app.SourceError, 'size/hash'): app.verify_input(directory, SOURCE, IMAGE)

    def test_receipt_missing_duplicate_unsafe_and_symlink_files_refuse(self):
        with tempfile.TemporaryDirectory() as t:
            directory, original = input_fixture(Path(t))
            for change in ('missing', 'duplicate', 'unsafe'):
                receipt = copy.deepcopy(original)
                if change == 'missing': receipt['files'] = receipt['files'][1:]
                if change == 'duplicate': receipt['files'].append(receipt['files'][0])
                if change == 'unsafe': receipt['files'][0]['file'] = '../escape'
                (directory / 'distribution-input.json').write_bytes(app.json_bytes(receipt))
                with self.assertRaises(app.SourceError): app.verify_input(directory, SOURCE, IMAGE)
            (directory / 'distribution-input.json').write_bytes(app.json_bytes(original))
            path = directory / 'guest-dpkg-status'; value = path.read_bytes(); path.unlink()
            target = directory / 'other'; target.write_bytes(value); path.symlink_to(target)
            with self.assertRaisesRegex(app.SourceError, 'regular'): app.verify_input(directory, SOURCE, IMAGE)

    def test_exact_source_fallback_epoch_bin_nmu_continuations_and_built_using_union(self):
        text = status(extra='Built-Using: gcc-14 (= 14.2.0-19),\n libc-src (= 2:2.41-12)\nStatic-Built-Using: rustc (= 1.85.0+dfsg3-1)\n')
        text += 'Package: fallback\nStatus: hold ok installed\nArchitecture: all\nVersion: 2.0+deb13u1\n\n'
        tsv = 'hello-bin:amd64\t1:2.0-3+b1\thello-src\t1:2.0-3\nfallback\t2.0+deb13u1\tfallback\t2.0+deb13u1\n'
        binaries, skipped, closure = app.source_closure(text, tsv)
        self.assertEqual(len(binaries), 2); self.assertEqual(skipped, [])
        self.assertEqual(set(closure), {('hello-src', '1:2.0-3'), ('fallback', '2.0+deb13u1'), ('gcc-14', '14.2.0-19'), ('libc-src', '2:2.41-12'), ('rustc', '1.85.0+dfsg3-1')})
        self.assertEqual(closure[('rustc', '1.85.0+dfsg3-1')][0]['field'], 'static-built-using')

    def test_inventory_drift_and_nonexact_or_ambiguous_control_metadata_refuse(self):
        tsv = 'hello-bin\t1:2.0-3+b1\thello-src\t1:2.0-3\n'
        for text in [status(extra='Built-Using: gcc-14 (>= 14)\n'), status(extra='Built-Using: gcc-14 (= 14) | gcc-15 (= 15)\n'), status() + status(), status(extra='Source: another\n')]:
            with self.assertRaises(app.SourceError): app.source_closure(text, tsv)
        for bad in [tsv.replace('1:2.0-3\n', '1:2.0-4\n'), '', tsv + tsv, 'wrong\tformat\n']:
            with self.assertRaises(app.SourceError): app.source_closure(status(), bad)

    def test_config_only_retained_versions_are_included_and_uninstalled_without_version_is_explicit(self):
        text = status().replace('install ok installed', 'deinstall ok config-files') + 'Package: gone\nStatus: purge ok not-installed\n\n'
        binaries, skipped, closure = app.source_closure(text, 'hello-bin\t1:2.0-3+b1\thello-src\t1:2.0-3\ngone\t\t\t\n')
        self.assertEqual(binaries[0]['status'], 'deinstall ok config-files')
        self.assertIn(('hello-src', '1:2.0-3'), closure); self.assertEqual(skipped[0]['package'], 'gone')


class ExactSourceAcquisition(unittest.TestCase):
    def test_exact_source_reuse_keeps_archive_bytes_and_refreshes_runtime_bindings_without_network(self):
        with tempfile.TemporaryDirectory(prefix='source reuse ') as t, FixtureServer() as server:
            root = Path(t); directory, receipt = input_fixture(root); server.source()
            prior = root / 'prior'
            original = app.build(directory, prior, SOURCE, IMAGE, transport=server.transport)
            original_index_sha = app.file_hash(prior / 'source-index.json')
            updated_source, updated_image = 'c' * 40, 'd' * 64
            receipt.update(source=updated_source, runtimeSource=updated_source, imageSha256=updated_image)
            support = b'new runtime source support'
            (directory / 'guest-distribution-support.tar.gz').write_bytes(support)
            support_record = next(row for row in receipt['files'] if row['file'] == 'guest-distribution-support.tar.gz')
            support_record.update(bytes=len(support), sha256=h(support))
            (directory / 'distribution-input.json').write_bytes(app.json_bytes(receipt))
            def forbidden(*args, **kwargs): raise AssertionError('source reuse must not acquire source metadata or blobs')
            output = root / 'new'
            reused = app.build(directory, output, updated_source, updated_image, transport=forbidden,
                               reuse_dir=prior, reuse_index_sha256=original_index_sha)
            self.assertTrue(reused['complete'])
            self.assertEqual(reused['packages'], original['packages'])
            self.assertEqual(reused['assets'], original['assets'])
            self.assertEqual(reused['source'], updated_source); self.assertEqual(reused['runtimeSource'], updated_source)
            self.assertEqual(reused['imageSha256'], updated_image)
            self.assertEqual(reused['consumerReceiptSha256'], app.file_hash(directory / 'distribution-input.json'))
            self.assertEqual(reused['sourceReuse'], {'indexSha256': original_index_sha, 'source': SOURCE,
                                                     'imageSha256': IMAGE, 'inventoryUnchanged': True})
            self.assertEqual((output / 'guest-distribution-support.tar.gz').read_bytes(), support)
            for asset in reused['assets']:
                self.assertEqual((output / asset['file']).read_bytes(), (prior / asset['file']).read_bytes())
            for line in (output / 'SHA256SUMS').read_text().splitlines():
                digest, name = line.split('  '); self.assertEqual(app.file_hash(output / name), digest)

    def test_source_reuse_refuses_changed_inventory_index_archive_and_missing_source_records(self):
        with tempfile.TemporaryDirectory(prefix='source reuse refusal ') as t, FixtureServer() as server:
            root = Path(t); directory, receipt = input_fixture(root); server.source()
            prior = root / 'prior'
            original = app.build(directory, prior, SOURCE, IMAGE, transport=server.transport)
            original_bytes = (prior / 'source-index.json').read_bytes()
            original_sha = h(original_bytes)
            def reuse(name, wanted=original_sha):
                return app.build(directory, root / name, SOURCE, IMAGE, reuse_dir=prior, reuse_index_sha256=wanted)
            with self.assertRaisesRegex(app.SourceError, 'index hash mismatch'):
                reuse('wrong-index', 'e' * 64)
            for key, value in [('complete', False), ('packages', []), ('assets', [])]:
                changed = copy.deepcopy(original); changed[key] = value
                raw = app.json_bytes(changed); (prior / 'source-index.json').write_bytes(raw)
                with self.subTest(key=key), self.assertRaises(app.SourceError): reuse('bad-' + key, h(raw))
            (prior / 'source-index.json').write_bytes(original_bytes)
            archive = prior / original['assets'][0]['file']; archive_bytes = archive.read_bytes()
            archive.write_bytes(archive_bytes + b'changed')
            with self.assertRaisesRegex(app.SourceError, 'archive size/hash mismatch'):
                reuse('bad-archive')
            archive.write_bytes(archive_bytes)
            changed_status = (directory / 'guest-dpkg-status').read_bytes().replace(b'install ok installed', b'deinstall ok config-files')
            (directory / 'guest-dpkg-status').write_bytes(changed_status)
            record = next(row for row in receipt['files'] if row['file'] == 'guest-dpkg-status')
            record.update(bytes=len(changed_status), sha256=h(changed_status))
            (directory / 'distribution-input.json').write_bytes(app.json_bytes(receipt))
            with self.assertRaisesRegex(app.SourceError, 'inventory differs'):
                reuse('changed-inventory')

    def test_complete_http_acquisition_keeps_dsc_all_sha256_files_and_checked_tar_index(self):
        with tempfile.TemporaryDirectory(prefix='source fixture ') as t, FixtureServer() as server:
            root = Path(t); directory, _ = input_fixture(root); _, expected = server.source()
            result = app.build(directory, root / 'output', SOURCE, IMAGE, transport=server.transport)
            self.assertTrue(result['complete']); self.assertEqual(result['missing'], [])
            self.assertEqual((root / 'output' / 'guest-distribution-support.tar.gz').read_bytes(), b'synthetic separate notices only')
            package = result['packages'][0]
            self.assertTrue(package['dscSignedEnvelope']); self.assertFalse(package['openPgpSignatureVerified'])
            self.assertEqual({f['name'] for f in package['files']}, set(expected))
            for asset in result['assets']:
                archive = root / 'output' / asset['file']; self.assertEqual(app.file_hash(archive), asset['sha256']); self.assertLess(asset['bytes'], 2 ** 31)
                with tarfile.open(archive) as tar:
                    self.assertTrue(all(member.isreg() for member in tar.getmembers()))
                    for record in package['files']:
                        if record['asset'] == asset['file']:
                            self.assertEqual(tar.extractfile(record['member']).read(), expected[record['name']])
            self.assertEqual(len({str(Path(f['member']).parent) for f in package['files']}), 1, 'dsc and payload basenames reconstruct in one directory')
            for line in (root / 'output' / 'SHA256SUMS').read_text().splitlines():
                digest, name = line.split('  '); self.assertEqual(app.file_hash(root / 'output' / name), digest)
            before = len([p for p in server.requests if p.startswith('/file/')])
            again = app.build(directory, root / 'again', SOURCE, IMAGE, cache=root / 'output' / 'cache', transport=server.transport)
            self.assertTrue(again['complete']); self.assertEqual(len([p for p in server.requests if p.startswith('/file/')]), before, 'verified retained cache avoids repeat source downloads')

    def test_missing_exact_version_is_explicit_without_latest_lookup_or_archives(self):
        with tempfile.TemporaryDirectory() as t, FixtureServer() as server:
            root = Path(t); directory, _ = input_fixture(root)
            server.source(version='1:2.0-4')
            result = app.build(directory, root / 'output', SOURCE, IMAGE, transport=server.transport)
            self.assertFalse(result['complete']); self.assertEqual(result['missing'][0]['version'], '1:2.0-3'); self.assertEqual(result['assets'], [])
            self.assertEqual(server.requests, ['/mr/package/hello-src/1%3A2.0-3/srcfiles?fileinfo=1'])
            self.assertFalse(list((root / 'output').glob('*.tar')))

    def test_bad_file_digest_or_truncation_and_dsc_wrong_version_do_not_complete(self):
        with tempfile.TemporaryDirectory() as t, FixtureServer() as server:
            root = Path(t); directory, _ = input_fixture(root); path, files = server.source(corrupt=True)
            result = app.build(directory, root / 'badstream', SOURCE, IMAGE, transport=server.transport)
            self.assertFalse(result['complete']); self.assertIn('size', result['missing'][0]['reason'])
            # Consistent API locator for a descriptor from another source identity
            # still cannot satisfy the requested exact .dsc/header version.
            metadata = json.loads(server.routes[path]); metadata['version'] = '1:2.0-4'
            server.routes[path] = json.dumps(metadata).encode()
            result = app.build(directory, root / 'badversion', SOURCE, IMAGE, transport=server.transport)
            self.assertFalse(result['complete']); self.assertIn('another package/version', result['missing'][0]['reason'])

    def test_dsc_identity_and_sha256_are_checked_even_when_api_sha1_metadata_matches(self):
        with tempfile.TemporaryDirectory() as t, FixtureServer() as server:
            root = Path(t); directory, _ = input_fixture(root); path, files = server.source()
            metadata = json.loads(server.routes[path])
            dsc_name = 'hello-src_2.0-3.dsc'
            original = files[dsc_name]; changed = original.replace(b'Version: 1:2.0-3', b'Version: 1:2.0-4')
            old_hash, new_hash = h(original, 'sha1'), h(changed, 'sha1')
            metadata['fileinfo'][new_hash] = metadata['fileinfo'].pop(old_hash)
            metadata['fileinfo'][new_hash][0]['size'] = len(changed)
            for entry in metadata['result']:
                if entry['hash'] == old_hash: entry['hash'] = new_hash
            server.routes[path] = json.dumps(metadata).encode(); server.routes['/file/' + new_hash] = changed
            result = app.build(directory, root / 'bad-dsc', SOURCE, IMAGE, transport=server.transport)
            self.assertFalse(result['complete']); self.assertIn('.dsc package/version', result['missing'][0]['reason'])
            # Restore the exact descriptor, but give one payload a matching API
            # SHA1 locator for different equal-length bytes. DSC SHA256 must win.
            path, files = server.source(); metadata = json.loads(server.routes[path])
            name = next(name for name in files if not name.endswith('.dsc'))
            original = files[name]; changed = b'X' + original[1:]
            old_hash, new_hash = h(original, 'sha1'), h(changed, 'sha1')
            metadata['fileinfo'][new_hash] = metadata['fileinfo'].pop(old_hash)
            for entry in metadata['result']:
                if entry['hash'] == old_hash: entry['hash'] = new_hash
            server.routes[path] = json.dumps(metadata).encode(); server.routes['/file/' + new_hash] = changed
            result = app.build(directory, root / 'bad-sha256', SOURCE, IMAGE, transport=server.transport)
            self.assertFalse(result['complete']); self.assertIn('size/hash mismatch', result['missing'][0]['reason'])
            self.assertEqual(result['assets'], [])

    def test_uncovered_members_unsafe_names_duplicate_tables_and_missing_sha256_refuse(self):
        base = {'checksums-sha256': '\n' + 'a' * 64 + ' 1 ok.tar.xz'}
        for fields in [{}, dict(base, files='\n' + 'b' * 32 + ' 1 other.tar.xz'), {'checksums-sha256': '\n' + 'a' * 64 + ' 1 ../escape'}, {'checksums-sha256': base['checksums-sha256'] * 2}]:
            with self.assertRaises(app.SourceError): app.dsc_members(fields)
        for name in ['../escape', '/absolute', 'a/b', 'a\\b', '-flag', 'space name', '.hidden', 'evil\nname']:
            with self.assertRaises(app.SourceError): app.basename(name)
        with self.assertRaises(app.SourceError): app.dsc_fields(b'-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nSource: hi\n')

    def test_official_transport_refuses_external_redirects_and_insecure_urls(self):
        for url in ['http://snapshot.debian.org/file/' + 'a' * 40, 'https://evil.invalid/file/a', 'https://snapshot.debian.org:443/file/a', 'file:///tmp/source', 'https://user@snapshot.debian.org/file/a']:
            with self.assertRaises(app.SourceError): app.official_url(url)
        handler = app.OfficialRedirect(); request = urllib.request.Request(app.ORIGIN + '/file/' + 'a' * 40)
        with self.assertRaises(app.SourceError): handler.redirect_request(request, None, 302, 'redirect', {}, 'https://evil.invalid/source')

    def test_plan_mode_verifies_inputs_and_exact_union_without_any_network(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); directory, _ = input_fixture(root)
            def forbidden(*args, **kwargs): raise AssertionError('plan must not access network')
            result = app.build(directory, root / 'plan', SOURCE, IMAGE, plan_only=True, transport=forbidden)
            self.assertTrue(result['planOnly']); self.assertFalse(result['complete']); self.assertEqual(result['packages'], [])
            self.assertEqual(result['required'][0]['version'], '1:2.0-3')
            with self.assertRaisesRegex(app.SourceError, 'output already exists'):
                app.build(directory, root / 'plan', SOURCE, IMAGE, plan_only=True, transport=forbidden)

    def test_tar_parts_obey_real_byte_cap_include_every_member_and_are_deterministic(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); paths = []
            for i in range(3):
                path = root / str(i); path.write_bytes(bytes([i]) * 11000); paths.append(path)
            def packages():
                return [{'package': 'fixture', 'version': '1.0', 'files': [{'name': f'file-{i}.tar.xz', 'local': p, 'sha256': app.file_hash(p), 'bytes': p.stat().st_size} for i, p in enumerate(paths)]}]
            a, b = root / 'a', root / 'b'; a.mkdir(); b.mkdir()
            first = app.pack_sources(a, packages(), 20480); second = app.pack_sources(b, packages(), 20480)
            self.assertEqual(first, second); self.assertEqual(len(first), 3)
            self.assertTrue(all(asset['bytes'] <= 20480 for asset in first))
            with self.assertRaisesRegex(app.SourceError, 'cannot fit'):
                app.pack_sources(root, packages(), 10240)


if __name__ == '__main__':
    unittest.main()
