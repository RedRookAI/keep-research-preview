"""Small frozen-tar permission regressions; no downloads, native build or VM."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('image_recipe', Path(__file__).with_name('build_image.py'))
recipe = importlib.util.module_from_spec(spec); spec.loader.exec_module(recipe)


class FrozenArchiveModes(unittest.TestCase):
    def test_private_umask_does_not_change_frozen_native_modes(self):
        with tempfile.TemporaryDirectory(prefix='native modes ') as temporary:
            root = Path(temporary); archive = root / 'frozen archive.tgz'
            wrong = root / 'masked extraction'; wrong.mkdir()
            good = root / 'preserved extraction'; good.mkdir()
            contents = {'manifest.json': (b'fixed manifest\n', 0o444), 'native-client': (b'fixed executable fixture\n', 0o555)}
            with tarfile.open(archive, 'w:gz') as stream:
                for name, (data, mode) in contents.items():
                    info = tarfile.TarInfo(name); info.mode = mode; info.size = len(data)
                    stream.addfile(info, io.BytesIO(data))
            previous = os.umask(0o077)
            try:
                # GNU tar's nonroot default is modeled explicitly so this also
                # reproduces the CI behavior when a local developer is root.
                env = {**os.environ, 'TAR_OPTIONS': '--no-same-permissions'}
                subprocess.run(['tar', '-xzf', str(archive), '-C', str(wrong)], env=env, check=True)
                self.assertEqual((wrong / 'manifest.json').stat().st_mode & 0o777, 0o400)
                self.assertEqual((wrong / 'native-client').stat().st_mode & 0o777, 0o500)
                with patch.dict(os.environ, {'TAR_OPTIONS': '--no-same-permissions'}):
                    recipe.extract_baseline(archive, good)
                for name, (data, mode) in contents.items():
                    expected = {'name': name, 'sha256': hashlib.sha256(data).hexdigest(), 'modeOctal': oct(mode)}
                    self.assertEqual((good / name).stat().st_mode & 0o777, mode)
                    recipe.verify_carried_native(good / name, expected)
                    with self.assertRaisesRegex(RuntimeError, 'expected_mode=.*actual_mode='):
                        recipe.verify_carried_native(wrong / name, expected)
            finally: os.umask(previous)

    def test_hash_or_permission_tampering_still_refuses(self):
        with tempfile.TemporaryDirectory(prefix='native tamper ') as temporary:
            artifact = Path(temporary) / 'native'; data = b'fixed native bytes'
            artifact.write_bytes(data); artifact.chmod(0o555)
            expected = {'name': 'native', 'sha256': hashlib.sha256(data).hexdigest(), 'modeOctal': '0o555'}
            recipe.verify_carried_native(artifact, expected)
            artifact.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, 'identity/mode mismatch'): recipe.verify_carried_native(artifact, expected)
            artifact.write_bytes(b'changed native bytes'); artifact.chmod(0o555)
            with self.assertRaisesRegex(RuntimeError, 'expected_sha256=.*actual_sha256='): recipe.verify_carried_native(artifact, expected)


if __name__ == '__main__': unittest.main()
