"""Small frozen-tar permission regressions; no downloads, native build or VM."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import pty
import select
import subprocess
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('image_recipe', Path(__file__).with_name('build_image.py'))
recipe = importlib.util.module_from_spec(spec); spec.loader.exec_module(recipe)


class FrozenArchiveModes(unittest.TestCase):
    def test_new_public_support_modes_survive_runtime_archive_without_touching_native_or_private_state(self):
        with tempfile.TemporaryDirectory(prefix='public support modes ') as temporary:
            root = Path(temporary); runtime = root / 'runtime'; runtime.mkdir()
            integrations = runtime / 'integrations'; integrations.mkdir()
            previous = os.umask(0o077)
            try:
                plugin = integrations / 'openclaw'; plugin.mkdir()
                packed = plugin / 'candidate-plugin.tgz'; packed.write_bytes(b'fixed plugin fixture')
                source = runtime / 'source-support.tar.gz'; source.write_bytes(b'fixed source fixture')
                private = root / 'private state'; private.mkdir()
                token = private / 'token'; token.write_bytes(b'private fixture')
            finally: os.umask(previous)
            self.assertEqual(plugin.stat().st_mode & 0o777, 0o700)
            self.assertEqual(source.stat().st_mode & 0o777, 0o600)
            native = runtime / 'native'; native.mkdir()
            native_inputs = {}
            for name, mode in [('manifest.json', 0o444), ('native-client', 0o555)]:
                artifact = native / name; artifact.write_bytes(name.encode()); artifact.chmod(mode)
                native_inputs[name] = {'name': name, 'sha256': recipe.sha(artifact), 'modeOctal': oct(mode)}
            source_hashes = {p: recipe.sha(p) for p in (source, packed)}
            recipe.publish_generated_runtime_support(runtime)
            self.assertEqual(plugin.stat().st_mode & 0o777, 0o755)
            for artifact, digest in source_hashes.items():
                self.assertEqual(artifact.stat().st_mode & 0o777, 0o444)
                self.assertEqual(recipe.sha(artifact), digest)
            for name, expected in native_inputs.items(): recipe.verify_carried_native(native / name, expected)
            self.assertEqual(private.stat().st_mode & 0o777, 0o700)
            self.assertEqual(token.stat().st_mode & 0o777, 0o600)
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            archive = root / 'runtime.tgz'
            subprocess.run(['tar', '-czf', str(archive), '-C', str(runtime), '.'], check=True)
            with tarfile.open(archive) as stream:
                self.assertEqual(stream.getmember('./integrations/openclaw').mode, 0o755)
                self.assertEqual(stream.getmember('./integrations/openclaw/candidate-plugin.tgz').mode, 0o444)
                self.assertEqual(stream.getmember('./source-support.tar.gz').mode, 0o444)
                for name, expected in native_inputs.items():
                    self.assertEqual(stream.getmember('./native/' + name).mode, int(expected['modeOctal'], 8))

    def test_background_sanitization_reaches_tty_and_survives_hangup(self):
        with tempfile.TemporaryDirectory(prefix='freeze tty ') as temporary:
            root = Path(temporary); script = root / 'freeze step.sh'
            script.write_text("#!/bin/sh\nkill -HUP \"$$\"\nprintf '%s\\n' 'freeze diagnostic' >&2\nprintf '%s\\n' 'KC111_IMAGE_SANITIZED'\n")
            script.chmod(0o700)
            master, slave = pty.openpty()
            try:
                subprocess.run(recipe.background_freeze(str(script), os.ttyname(slave)),
                    cwd=root, check=True, capture_output=True, timeout=5)
                output = b''; deadline = time.monotonic() + 2
                while b'KC111_IMAGE_SANITIZED' not in output:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0: break
                    if select.select([master], [], [], remaining)[0]:
                        output += os.read(master, 4096)
                self.assertIn(b'freeze diagnostic', output)
                self.assertIn(b'KC111_IMAGE_SANITIZED', output)
                self.assertFalse((root / 'nohup.out').exists())
            finally:
                os.close(master); os.close(slave)

    def test_background_sanitization_stdout_and_stderr_reach_selected_serial_sink(self):
        with tempfile.TemporaryDirectory(prefix='freeze serial ') as temporary:
            root = Path(temporary); script = root / 'freeze step.sh'; sink = root / 'selected serial sink'
            script.write_text("#!/bin/sh\nprintf '%s\\n' 'freeze diagnostic' >&2\nprintf '%s\\n' 'KC111_IMAGE_SANITIZED'\n")
            script.chmod(0o700)
            subprocess.run(recipe.background_freeze(str(script), sink), check=True, capture_output=True, timeout=5)
            deadline = time.monotonic() + 2
            while not sink.exists() or 'KC111_IMAGE_SANITIZED' not in sink.read_text():
                if time.monotonic() >= deadline: self.fail('background freeze output did not reach selected sink')
                time.sleep(0.01)
            self.assertEqual(sink.read_text().splitlines(), ['freeze diagnostic', 'KC111_IMAGE_SANITIZED'])

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
