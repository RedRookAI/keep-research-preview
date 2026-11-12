"""Deterministic post-signal argv teardown and pre-signal ownership regressions."""
import hashlib
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


host = load('host_stop', 'keep-appliance.py')
guest = load('guest_stop', 'guest-control.py')


class StopObservation(unittest.TestCase):
    def test_argv_cleared_before_z_does_not_invalidate_an_already_admitted_stop(self):
        for module in (host, guest):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory(prefix='stop regression ') as temporary:
                child = subprocess.Popen(['sleep', '30'])
                try:
                    record = module.identity(child.pid)
                    signaled, identity_reads = [], []
                    states = iter(['R', 'R', 'Z', 'Z'])

                    def identity(pid):
                        identity_reads.append(True)
                        # Old alive()-after-signal polling would read empty argv
                        # here while /proc/stat could still show a running state.
                        return dict(record, argvSha256=hashlib.sha256(b'').hexdigest()) if signaled else record

                    def stop_state(pid):
                        return {'uid': record['uid'], 'start': record['start'], 'state': next(states)}

                    with patch.object(module, 'identity', side_effect=identity), patch.object(module, 'read_stop_state', side_effect=stop_state), patch.object(module.os, 'kill', side_effect=lambda pid, sig: signaled.append((pid, sig))), patch.object(module.time, 'sleep'), patch.object(guest, 'ROOT', Path(temporary)):
                        if module is host: module.terminate(record)
                        else: module.stop_sample({'schema': 'keep.appliance.sample-control/v1', 'stage': 'running', 'process': record})
                    self.assertEqual(signaled, [(child.pid, signal.SIGTERM)])
                    self.assertEqual(len(identity_reads), 1, 'complete identity is checked once before signal; not replaced by an exit-only guard')
                    self.assertIsNone(child.poll(), 'modeled exit observation sends no extra real signals')
                finally:
                    child.terminate(); child.wait()

    def test_unexpected_identity_before_signal_still_refuses(self):
        for module in (host, guest):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory(prefix='mismatch regression ') as temporary:
                child = subprocess.Popen(['sleep', '30'])
                try:
                    record = module.identity(child.pid)
                    record['argvSha256'] = '0' * 64
                    with patch.object(module.os, 'kill') as kill, patch.object(guest, 'ROOT', Path(temporary)):
                        with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                            if module is host: module.terminate(record)
                            else: module.stop_sample({'stage': 'running', 'process': record})
                        kill.assert_not_called()
                    self.assertIsNone(child.poll())
                finally:
                    child.terminate(); child.wait()

    def test_pid_reuse_or_uid_change_while_waiting_remains_unresolved(self):
        for module in (host, guest):
            record = {'pid': 123, 'uid': os.getuid(), 'start': '50'}
            for change in ({'uid': record['uid'] + 1}, {'start': '51'}):
                with self.subTest(module=module.__name__, change=change), patch.object(module, 'read_stop_state', return_value={'uid': record['uid'], 'start': record['start'], 'state': 'R', **change}), patch.object(module.os, 'kill') as kill:
                    with self.assertRaisesRegex(RuntimeError, 'unresolved'): module.awaiting_exit(record)
                    kill.assert_not_called()


if __name__ == '__main__': unittest.main()
