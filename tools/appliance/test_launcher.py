"""Cheap host refusal/ownership checks; no image, installation or VM boot."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('keep_appliance', Path(__file__).with_name('keep-appliance.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class HostControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='appliance checks ')
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_private_instance_paths_with_spaces_are_preserved(self):
        path = self.root / 'my private instance'
        with app.instance(path, create=True) as (actual, data):
            self.assertEqual(actual, path)
            self.assertEqual(data['stage'], 'new')
        with app.instance(path) as (actual, data):
            self.assertEqual(actual, path)
            self.assertEqual(data['schema'], app.SCHEMA)
        self.assertEqual(path.stat().st_mode & 0o777, 0o700)

    def test_unknown_state_is_preserved_and_refused(self):
        path = self.root / 'unknown'; path.mkdir(mode=0o700)
        (path / 'valuable').write_text('preserve me')
        with self.assertRaisesRegex(RuntimeError, 'unknown state'):
            with app.instance(path, create=True):
                pass
        self.assertEqual((path / 'valuable').read_text(), 'preserve me')

    def test_other_bundle_record_is_not_adopted(self):
        path = self.root / 'foreign'; path.mkdir(mode=0o700)
        record = {'schema': app.SCHEMA, 'bundle': '/another/bundle'}
        (path / 'instance.json').write_text(json.dumps(record))
        with self.assertRaisesRegex(RuntimeError, 'another bundle'):
            with app.instance(path):
                pass
        self.assertEqual(json.loads((path / 'instance.json').read_text()), record)

    def test_symlink_state_is_refused(self):
        target = self.root / 'owned'; target.mkdir(mode=0o700)
        link = self.root / 'alias'; link.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'symlink'):
            app.private_directory(link)

    def test_occupied_port_is_refused_without_stopping_listener(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); listener.listen()
            port = listener.getsockname()[1]
            with self.assertRaisesRegex(RuntimeError, 'occupied'):
                app.port_available(port)
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                pass

    def test_wrong_architecture_fails_before_tool_or_policy_work(self):
        with patch.object(app.platform, 'machine', return_value='aarch64'):
            with self.assertRaisesRegex(RuntimeError, 'Linux x64'):
                app.prerequisites()

    def test_missing_tool_fails_without_installing_it(self):
        with patch.object(app.platform, 'machine', return_value='x86_64'), patch.object(app.os, 'getuid', return_value=1001), patch.object(app.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'Missing host prerequisite'):
                app.prerequisites()

    def test_inaccessible_kvm_names_operator_action(self):
        with patch.object(app.platform, 'machine', return_value='x86_64'), patch.object(app.os, 'getuid', return_value=1001), patch.object(app.shutil, 'which', return_value='/present/tool'), patch.object(app.os, 'access', return_value=False):
            with self.assertRaisesRegex(RuntimeError, 'host operator'):
                app.prerequisites()

    def test_changed_process_identity_is_never_signaled(self):
        child = subprocess.Popen(['sleep', '30'])
        try:
            record = app.identity(child.pid); record['start'] = '-1'
            with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                app.terminate(record)
            self.assertIsNone(child.poll())
        finally:
            child.terminate(); child.wait()

    def test_exited_child_is_not_a_live_resource(self):
        child = subprocess.Popen(['sleep', '0.1'])
        try:
            record = app.identity(child.pid)
            time.sleep(0.2)
            self.assertFalse(app.alive(record))
        finally:
            child.wait()

    def test_replaced_overlay_is_refused(self):
        path = self.root / 'disk'; path.mkdir()
        disk = path / 'instance.qcow2'; disk.write_text('first')
        old = disk.stat()
        data = {'overlay': {'device': old.st_dev, 'inode': old.st_ino}}
        disk.rename(path / 'retained-first')
        disk.write_text('replacement')
        with self.assertRaisesRegex(RuntimeError, 'overlay identity changed'):
            app.verify_overlay(path, data)
        self.assertEqual((path / 'retained-first').read_text(), 'first')


if __name__ == '__main__':
    unittest.main()
