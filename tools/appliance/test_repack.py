"""Tiny frozen-image repack/provenance regressions; no VM, npm or acquisition."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(path))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


recipe = load('repack_recipe', 'repack_image.py')
uploader = load('repack_uploader_contract', 'upload_candidate.py')


class Repack(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='frozen image repack ')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name); self.repo = self.root / 'source'; self.repo.mkdir()
        self.git('init', '--quiet')
        for path in [*recipe.HOST_FILES.values(), 'src/main.ts', 'bin/keep', 'package.json',
                     'package-lock.json', 'tools/appliance/guest-control.py', 'tools/appliance/guest-proof.mjs']:
            target = self.repo / path; target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('original ' + path + '\n')
        self.commit('image source'); self.image_source = self.head()
        (self.repo / 'tools/appliance/keep-appliance.py').write_text('reviewed corrected launcher\n')
        (self.repo / 'tools/appliance/consumer.py').write_text('reviewed corrected consumer\n')
        (self.repo / 'docs/reviewer-appliance.md').write_text('reviewed host guide\n')
        self.commit('host assembly'); self.source = self.head()
        self.image = b'frozen qcow2 fixture bytes'; self.image_hash = hashlib.sha256(self.image).hexdigest()
        self.components = {'schema': 'keep.appliance.image-build/v1', 'source': self.image_source,
                           'nodeVersion': '22.23.5', 'nodeExecutableSha256': 'a' * 64}
        self.files = {'keep.qcow2': self.image, 'image-build.json': self.encoded(self.components),
                      'keep-appliance.py': b'old launcher\n', 'qualify.py': b'old consumer\n',
                      'GUIDE.md': b'old guide\n', 'helper-source.tar.xz': b'unchanged source fixture'}
        self.manifest = {'schema': 'keep.appliance.bundle/v1', 'source': self.image_source,
                         'packageVersion': '0.0.27-preview.1', 'components': self.components,
                         'profile': {'diskVirtualBytes': 8192}, 'shippingCredentials': False,
                         'sampleContract': {'goal': 'fixed goal'},
                         'files': {name: hashlib.sha256(data).hexdigest() for name, data in self.files.items()}}
        self.files['manifest.json'] = self.encoded(self.manifest)
        self.files['SHA256SUMS'] = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
            for name, data in sorted(self.files.items())).encode()
        self.archive = self.root / 'original.tar.xz'; self.make_archive()
        self.original = {'source': self.image_source, 'archive': self.archive.name,
                         'sha256': recipe.digest(self.archive), 'compressedBytes': self.archive.stat().st_size,
                         'imageSha256': self.image_hash, 'imageBytes': len(self.image), 'diskVirtualBytes': 8192}
        self.candidate = self.root / 'original-candidate.json'; self.write_candidate()
        self.output = self.root / 'output'; self.bundle_name = 'keep-reviewer-0.0.27-preview.1-linux-x64'
        self.environment = patch.dict(os.environ, {'GITHUB_SHA': self.source, 'GITHUB_RUN_ID': '4321'})
        self.environment.start(); self.addCleanup(self.environment.stop)

    @staticmethod
    def encoded(value): return (json.dumps(value, indent=2) + '\n').encode()

    def git(self, *args):
        return subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
            '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', *args],
            cwd=self.repo, check=True, capture_output=True, text=True).stdout.strip()

    def commit(self, message): self.git('add', '.'); self.git('commit', '--quiet', '-m', message)
    def head(self): return self.git('rev-parse', 'HEAD')

    def make_archive(self, link=False):
        root = 'keep-reviewer-0.0.27-preview.1-linux-x64'
        with tarfile.open(self.archive, 'w:xz') as stream:
            directory = tarfile.TarInfo(root); directory.type = tarfile.DIRTYPE; directory.mode = 0o700
            stream.addfile(directory)
            for name, data in self.files.items():
                member = tarfile.TarInfo(root + '/' + name); member.mode = 0o444 if name == 'keep.qcow2' else 0o644
                member.size = len(data); stream.addfile(member, io.BytesIO(data))
            if link:
                member = tarfile.TarInfo(root + '/linked'); member.type = tarfile.SYMTYPE
                member.linkname = '/tmp/not-owned'; stream.addfile(member)

    def write_candidate(self):
        self.candidate.write_bytes(self.encoded({'schema': 'keep.appliance.candidate/v1', **self.original}))

    def refresh_archive_identity(self):
        self.original.update(sha256=recipe.digest(self.archive), compressedBytes=self.archive.stat().st_size)
        self.write_candidate()

    def run_repack(self):
        return recipe.repack(self.archive, self.candidate, self.output, self.repo, self.original)

    def test_same_image_modes_and_guest_receipt_with_new_committed_host_provenance(self):
        # Uncommitted host text cannot enter an assembly bound to the Git SHA.
        (self.repo / 'tools/appliance/keep-appliance.py').write_text('uncommitted text must not ship')
        result = self.run_repack()
        self.assertEqual(result['source'], self.source)
        self.assertEqual(result['sourceAssemblySHA'], self.source)
        self.assertEqual(result['imageSource'], self.image_source)
        self.assertFalse(result['consumerPassed'])
        self.assertEqual(result['imageSha256'], self.image_hash)
        self.assertEqual(uploader.verify_frozen_candidate(self.output, result, self.source), self.output / result['archive'])
        with tarfile.open(self.output / result['archive']) as stream:
            def data(name): return stream.extractfile(self.bundle_name + '/' + name).read()
            self.assertEqual(data('keep.qcow2'), self.image)
            self.assertEqual(stream.getmember(self.bundle_name + '/keep.qcow2').mode, 0o444)
            self.assertEqual(stream.getmember(self.bundle_name).mode, 0o700)
            self.assertEqual(data('keep-appliance.py'), b'reviewed corrected launcher\n')
            self.assertEqual(data('qualify.py'), b'reviewed corrected consumer\n')
            self.assertEqual(data('GUIDE.md'), b'reviewed host guide\n')
            self.assertEqual(data('image-build.json'), self.files['image-build.json'])
            self.assertEqual(data('helper-source.tar.xz'), self.files['helper-source.tar.xz'])
            manifest = json.loads(data('manifest.json'))
            self.assertEqual(manifest['source'], self.source)
            self.assertEqual(manifest['sourceAssemblySHA'], self.source)
            self.assertEqual(manifest['imageSource'], self.image_source)
            self.assertEqual(manifest['components'], self.components)
            self.assertNotIn('manifest.json', manifest['files']); self.assertNotIn('SHA256SUMS', manifest['files'])
            for name, wanted in manifest['files'].items(): self.assertEqual(hashlib.sha256(data(name)).hexdigest(), wanted)
            sums = {line.split('  ', 1)[1]: line.split('  ', 1)[0] for line in data('SHA256SUMS').decode().splitlines()}
            self.assertIn('manifest.json', sums); self.assertNotIn('SHA256SUMS', sums)
            for name, wanted in sums.items(): self.assertEqual(hashlib.sha256(data(name)).hexdigest(), wanted)
            with tarfile.open(fileobj=io.BytesIO(data('HOST_SOURCE.tar.gz'))) as source:
                self.assertEqual(source.extractfile('tools/appliance/keep-appliance.py').read(), b'reviewed corrected launcher\n')

    def test_archive_or_candidate_tampering_refuses_before_output(self):
        bad = json.loads(self.candidate.read_text()); bad['source'] = 'b' * 40
        self.candidate.write_bytes(self.encoded(bad))
        with self.assertRaisesRegex(RuntimeError, 'candidate receipt'): self.run_repack()
        self.write_candidate()
        with self.archive.open('ab') as stream: stream.write(b'altered transport')
        with self.assertRaisesRegex(RuntimeError, 'archive hash or size'): self.run_repack()
        self.assertFalse(self.output.exists())

    def test_original_manifest_file_and_image_provenance_are_checked(self):
        cases = [('file', 'manifest file hashes'), ('source', 'image provenance'),
                 ('image', 'image bytes'), ('receipt', 'guest build receipt')]
        baseline_files = copy.deepcopy(self.files); baseline_manifest = copy.deepcopy(self.manifest)
        for kind, message in cases:
            with self.subTest(kind=kind):
                self.files = copy.deepcopy(baseline_files); manifest = copy.deepcopy(baseline_manifest)
                if kind == 'file': self.files['GUIDE.md'] = b'tampered guide'
                elif kind == 'source': manifest['components']['source'] = 'b' * 40
                elif kind == 'image':
                    self.files['keep.qcow2'] = b'altered image'
                    manifest['files']['keep.qcow2'] = hashlib.sha256(self.files['keep.qcow2']).hexdigest()
                else:
                    self.files['image-build.json'] = b'{}\n'
                    manifest['files']['image-build.json'] = hashlib.sha256(self.files['image-build.json']).hexdigest()
                self.files['manifest.json'] = self.encoded(manifest)
                self.files['SHA256SUMS'] = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
                    for name, data in sorted(self.files.items()) if name != 'SHA256SUMS').encode()
                self.make_archive(); self.refresh_archive_identity()
                with self.assertRaisesRegex(RuntimeError, message): self.run_repack()
                self.assertFalse(self.output.exists())

    def test_guest_source_drift_or_wrong_assembly_environment_refuses(self):
        with patch.dict(os.environ, {'GITHUB_SHA': 'c' * 40}):
            with self.assertRaisesRegex(RuntimeError, 'assembly source'): self.run_repack()
        (self.repo / 'src/main.ts').write_text('changed guest code')
        self.commit('unapproved guest drift')
        with patch.dict(os.environ, {'GITHUB_SHA': self.head()}):
            with self.assertRaisesRegex(RuntimeError, 'Guest code/package differs'): self.run_repack()
        self.assertFalse(self.output.exists())

    def test_original_link_member_is_refused(self):
        self.make_archive(link=True); self.refresh_archive_identity()
        with self.assertRaisesRegex(RuntimeError, 'member type'): self.run_repack()
        self.assertFalse(self.output.exists())


if __name__ == '__main__': unittest.main()
