"""Crash-window tests use small owned sleep processes; never a VM or app job."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


host = load('host_control', 'keep-appliance.py')
guest = load('guest_control', 'guest-control.py')


class Crash(BaseException):
    pass


class DispatchDurability(unittest.TestCase):
    def test_host_handle_gap_preserves_intent_for_each_managed_process(self):
        for role in ('seed', 'qemu', 'tunnel'):
            with self.subTest(role=role), tempfile.TemporaryDirectory(prefix='host dispatch ') as temporary:
                root = Path(temporary)
                data = {'schema': host.SCHEMA, 'stage': 'starting', 'bundle': str(host.BUNDLE)}
                original_save = host.save
                children, saves, synced_directories = [], [], []
                original_fsync = os.fsync

                def sync(fd):
                    if stat.S_ISDIR(os.fstat(fd).st_mode): synced_directories.append(True)
                    original_fsync(fd)

                def save(path, value):
                    saves.append(True)
                    if len(saves) == 2: raise Crash('handle confirmation interrupted')
                    original_save(path, value)

                def spawn(argv, log, *, cwd=None):
                    pending = json.loads((root / 'instance.json').read_text())
                    self.assertEqual(pending['dispatches'][role]['state'], 'intent')
                    self.assertTrue(synced_directories, 'intent directory must be durable before spawn')
                    child = subprocess.Popen(['sleep', '30']); children.append(child)
                    return host.identity(child.pid)

                try:
                    with patch.object(host, 'save', side_effect=save), patch.object(host, 'spawn_owned', side_effect=spawn), patch.object(host.os, 'fsync', side_effect=sync):
                        with self.assertRaises(Crash):
                            host.dispatch_owned(root, data, role, ['fake'], root / 'log')
                    before = (root / 'instance.json').read_bytes()
                    recovered = json.loads(before)
                    self.assertNotIn(role, recovered)
                    with self.assertRaisesRegex(RuntimeError, 'Unresolved appliance dispatch'):
                        host.stop(root, recovered)
                    with self.assertRaisesRegex(RuntimeError, 'Unresolved appliance dispatch'):
                        host.start(root, recovered, 7788, 2222)
                    self.assertEqual((root / 'instance.json').read_bytes(), before)
                    self.assertEqual(len(children), 1)
                    self.assertIsNone(children[0].poll(), 'unknown child must not be guessed or signaled')
                finally:
                    for child in children: child.terminate(); child.wait()

    def test_managed_tunnel_retains_intent_and_launches_in_instance_cwd(self):
        with tempfile.TemporaryDirectory(prefix='tunnel instance ') as temporary:
            root = Path(temporary)
            (root / 'owner-key').write_text('owned key fixture')
            (root / 'known-hosts').write_text('owned host fixture')
            data = {'stage': 'running', 'port': 7788, 'sshPort': 2222}
            original_spawn, original_popen = host.spawn_owned, subprocess.Popen
            children = []

            def popen(*args, **kwargs):
                child = original_popen(*args, **kwargs); children.append(child); return child

            def spawn(argv, log, *, cwd=None):
                pending = json.loads((root / 'instance.json').read_text())
                self.assertEqual(pending['dispatches']['tunnel']['state'], 'intent')
                self.assertNotIn('tunnel', pending)
                self.assertEqual(cwd, root)
                self.assertIn('UserKnownHostsFile=known-hosts', argv)
                self.assertEqual(argv[argv.index('-i') + 1], 'owner-key')
                script = ('from pathlib import Path; import time; '
                          'print(Path("owner-key").read_text(), Path("known-hosts").read_text(), flush=True); '
                          'time.sleep(30)')
                return original_spawn([sys.executable, '-c', script], log, cwd=cwd)

            try:
                with patch.object(host, 'port_available'), patch.object(host, 'spawn_owned', side_effect=spawn), \
                     patch.object(host.subprocess, 'Popen', side_effect=popen):
                    host.tunnel(root, data)
                record = json.loads((root / 'instance.json').read_text())
                self.assertEqual(record['dispatches']['tunnel']['state'], 'confirmed')
                self.assertTrue(host.alive(record['tunnel']))
                # Wait for useful relative-file reads, then use the admitted owned handle.
                deadline = time.monotonic() + 5
                while not (root / 'tunnel.log').read_text() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual((root / 'tunnel.log').read_text().strip(), 'owned key fixture owned host fixture')
                host.terminate(record['tunnel'])
            finally:
                for child in children:
                    if child.poll() is None: child.terminate()
                    child.wait()

    def test_guest_handle_gap_cannot_be_cleared_by_stop_or_retry(self):
        with tempfile.TemporaryDirectory(prefix='guest dispatch ') as temporary, patch.object(guest, 'ROOT', Path(temporary)):
            data = {'schema': 'keep.appliance.sample-control/v1', 'stage': 'new'}
            original_write, original_popen = guest.write_state, subprocess.Popen
            children, writes = [], []

            def write(value):
                writes.append(True)
                if len(writes) == 2: raise Crash('confirmation interrupted')
                original_write(value)

            def spawn(*args, **kwargs):
                persisted = json.loads((guest.ROOT / 'control.json').read_text())
                self.assertEqual(persisted['stage'], 'starting')
                self.assertNotIn('process', persisted)
                child = original_popen(['sleep', '30']); children.append(child); return child

            try:
                with patch.object(guest, 'write_state', side_effect=write), patch.object(guest.subprocess, 'Popen', side_effect=spawn):
                    with self.assertRaises(Crash): guest.start_sample(data, 7788)
                before = (guest.ROOT / 'control.json').read_bytes()
                recovered = json.loads(before)
                with self.assertRaisesRegex(RuntimeError, 'no confirmed handle'):
                    guest.stop_sample(recovered)
                with self.assertRaisesRegex(RuntimeError, 'unresolved'):
                    guest.start_sample(recovered, 7788)
                self.assertEqual((guest.ROOT / 'control.json').read_bytes(), before)
                self.assertEqual(len(children), 1); self.assertIsNone(children[0].poll())
            finally:
                for child in children: child.terminate(); child.wait()

    def test_immediate_guest_ready_event_is_not_absorbed_into_baseline(self):
        with tempfile.TemporaryDirectory(prefix='fast ready ') as temporary, patch.object(guest, 'ROOT', Path(temporary)):
            original_popen = subprocess.Popen
            children = []

            def spawn(*args, **kwargs):
                kwargs['stdout'].write((json.dumps({'event': 'sample-ready', 'scripted': True}) + '\n').encode())
                child = original_popen(['sleep', '30']); children.append(child); return child

            try:
                data = {'schema': 'keep.appliance.sample-control/v1', 'stage': 'new'}
                with patch.object(guest.subprocess, 'Popen', side_effect=spawn): guest.start_sample(data, 7788)
                self.assertEqual(data['stage'], 'running')
                self.assertEqual(data['eventsBeforeStart'], 0)
                guest.stop_sample(data)
                self.assertEqual(data['stage'], 'stopped')
            finally:
                for child in children:
                    if child.poll() is None: child.terminate()
                    child.wait()


if __name__ == '__main__': unittest.main()
