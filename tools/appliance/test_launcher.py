"""Cheap host refusal/ownership checks; no image, installation or VM boot."""
import importlib.util
import errno
import hashlib
import io
import json
import os
import shlex
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location('keep_appliance', Path(__file__).with_name('keep-appliance.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class HostControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='appliance checks ')
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def check_sample_page(self, body):
        notice = 'Scripted demo · two authored responses · real edits and checks · no AI account or paid calls.'
        (self.root / 'manifest.json').write_text(json.dumps({'sampleContract': {'notice': notice}}))
        with patch.object(app, 'BUNDLE', self.root), patch.object(app, 'refuse_pending'), \
             patch.object(app, 'verify_overlay'), patch.object(app, 'tunnel'), \
             patch.object(app, 'guest', return_value=SimpleNamespace(stdout='{"status":"running"}')), \
             patch.object(app.urllib.request, 'urlopen', return_value=io.BytesIO(body.encode())):
            return app.sample(self.root, {'port': 7788}, 'start')

    def test_sample_readiness_accepts_retained_actual_guided_signin(self):
        fixture = Path(__file__).with_name('test-data') / 'guided-signin.html'
        metadata = json.loads(fixture.with_suffix('.json').read_text())
        self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(), metadata['sha256'])
        self.assertEqual(metadata['rendererBlob'], '27f41b0450ac0a78b9a49275d0888e9083e8a9ed')
        self.assertIn('fbd88f7c0190da905b49809290dfa496af290e10', metadata['rendererSameInSources'])
        self.assertTrue(metadata['unauthenticatedGetOnly'])
        self.assertFalse(metadata['sampleStarted'])
        self.assertFalse(metadata['credentialsInBody'])
        body = fixture.read_text()
        self.assertIn('Invitation credential', body)
        self.assertNotIn('Instance credential', body)
        result = self.check_sample_page(body)
        self.assertEqual(result['checkedBrowserOrigin'], 'http://127.0.0.1:7788/console')

    def test_sample_readiness_accepts_decoded_notice_and_label_changes(self):
        body = (Path(__file__).with_name('test-data') / 'guided-signin.html').read_text()
        body = body.replace('·', '&#183;').replace('Invitation credential', 'Reviewer access')
        self.assertEqual(self.check_sample_page(body)['status'], 'running')

    def test_sample_readiness_refuses_wrong_notice_and_nonlogin_pages(self):
        body = (Path(__file__).with_name('test-data') / 'guided-signin.html').read_text()
        notice = 'Scripted demo · two authored responses · real edits and checks · no AI account or paid calls.'
        cases = {
            'wrong notice': body.replace('two authored responses', 'three authored responses'),
            'personal signin': body.replace(notice, '').replace('Invitation credential', 'Instance credential'),
            'wrong action': body.replace('action="/console/login"', 'action="/console/logout"'),
            'non-post form': body.replace('method="post"', 'method="get"'),
            'non-password input': body.replace('type="password"', 'type="text"'),
            'wrong credential field': body.replace('name="token"', 'name="other"'),
            'token outside login form': body.replace('<input', '</form><input'),
            'old fake bare-text positive': 'Instance credential ' + notice,
            'notice only in script': body.replace('<p class="notice">' + notice + '</p>',
                                                 '<script>' + notice + '</script>'),
        }
        for name, altered in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'did not identify'):
                self.check_sample_page(altered)

    def test_failed_sample_control_retains_bounded_real_stderr_and_excludes_stdout(self):
        secret = 'private invitation stdout sentinel'
        diagnostic = 'Sample control refused: exact controlled failure: ' + 'x' * 9000
        data = {'port': 7788, 'tunnel': {'retained': True}}

        def guest(path, state, argv, **options):
            self.assertEqual(argv, ['keep-reviewer', 'stop', '7788'])
            self.assertEqual(options, {'capture_output': True, 'text': True})
            script = 'import sys;sys.stdout.write(' + repr(secret) + ');sys.stderr.write(' + repr(diagnostic) + ');raise SystemExit(7)'
            return app.command([sys.executable, '-c', script], **options)

        with patch.object(app, 'refuse_pending'), patch.object(app, 'verify_overlay'), \
             patch.object(app, 'guest', side_effect=guest), patch.object(app, 'terminate') as terminate:
            with self.assertRaises(RuntimeError) as captured:
                app.sample(self.root, data, 'stop')
            terminate.assert_not_called()
        prefix = 'Guest sample control stop failed (exit 7): '
        self.assertEqual(str(captured.exception), prefix + diagnostic[:8192])
        self.assertNotIn(secret, str(captured.exception))
        self.assertEqual(data, {'port': 7788, 'tunnel': {'retained': True}})

    def test_private_instance_paths_with_spaces_are_preserved(self):
        path = self.root / 'my private instance'
        with app.instance(path, create=True) as (actual, data):
            self.assertEqual(actual, path)
            self.assertEqual(data['stage'], 'new')
        with app.instance(path) as (actual, data):
            self.assertEqual(actual, path)
            self.assertEqual(data['schema'], app.SCHEMA)
        self.assertEqual(path.stat().st_mode & 0o777, 0o700)

    def test_openssh_parses_one_relative_credential_path_in_spaced_instance(self):
        path = self.root / 'instance 1 %h'; path.mkdir(mode=0o700)
        (path / 'owner-key').write_text('parser fixture only')
        data = {'sshPort': 2222}
        for pinned, policy in ((False, 'accept-new'), (True, 'true')):
            with self.subTest(pinned=pinned):
                if pinned: (path / 'known-hosts').write_text('retained host key')
                result = subprocess.run(app.ssh_options(path, data) + ['-G', 'keep@127.0.0.1'],
                                        cwd=path, check=True, capture_output=True, text=True)
                parsed = dict(line.split(' ', 1) for line in result.stdout.splitlines())
                self.assertEqual(parsed['userknownhostsfile'], 'known-hosts')
                self.assertEqual(parsed['identityfile'], 'owner-key')
                self.assertEqual(parsed['globalknownhostsfile'], '/dev/null')
                self.assertEqual(parsed['stricthostkeychecking'], policy)
                self.assertEqual(parsed['identitiesonly'], 'yes')

    def test_guest_and_interactive_shell_use_validated_instance_cwd(self):
        path = self.root / 'instance 1'
        with app.instance(path, create=True) as (_, data):
            data['sshPort'] = 2222
            app.save(path / 'instance.json', data)
        argv = ['printf', '%s', 'argument with spaces']
        with patch.object(app, 'alive', return_value=True), patch.object(app, 'verify_overlay'), \
             patch.object(app, 'command') as command:
            app.guest(path, {'sshPort': 2222, 'qemu': {}}, argv, capture_output=True)
            self.assertEqual(command.call_args.kwargs['cwd'], path)
            self.assertEqual(command.call_args.args[0][-1], shlex.join(argv))
            self.assertTrue(command.call_args.kwargs['capture_output'])
        with patch.object(app.sys, 'argv', ['keep-appliance', 'shell', str(path)]), \
             patch.object(app, 'command') as command:
            app.main()
            self.assertEqual(command.call_args.kwargs, {'cwd': path, 'timeout': None})
            self.assertEqual(command.call_args.args[0][-2:], ['-t', 'keep@127.0.0.1'])

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

    def test_recently_used_forward_port_can_be_probed_without_waiting(self):
        listener = socket.socket(); listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', 0)); listener.listen()
        port = listener.getsockname()[1]
        client = socket.socket(); peer = None
        try:
            client.connect(('127.0.0.1', port)); peer, _ = listener.accept()
            peer.sendall(b'fixture'); self.assertEqual(client.recv(7), b'fixture')
            listener.close()
            peer.shutdown(socket.SHUT_WR); self.assertEqual(client.recv(1), b'')
            client.close(); self.assertEqual(peer.recv(1), b''); peer.close()
            with socket.socket() as bare:
                with self.assertRaises(OSError) as captured:
                    bare.bind(('127.0.0.1', port))
                self.assertEqual(captured.exception.errno, errno.EADDRINUSE)
            app.port_available(port)
        finally:
            listener.close(); client.close()
            if peer: peer.close()

    def test_reuse_enabled_live_listener_is_still_refused_and_untouched(self):
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('127.0.0.1', 0)); listener.listen()
            port = listener.getsockname()[1]
            with self.assertRaisesRegex(RuntimeError, 'occupied'):
                app.port_available(port)
            with socket.create_connection(('127.0.0.1', port)):
                peer, _ = listener.accept(); peer.close()

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
