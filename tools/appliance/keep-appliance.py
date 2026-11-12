#!/usr/bin/env python3
"""Owned Linux x64 QEMU/KVM appliance. Python standard library only."""
import argparse
import contextlib
import fcntl
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
import urllib.request
import uuid

BUNDLE = Path(__file__).resolve().parent
SCHEMA = 'keep.appliance.instance/v1'


def fail(message):
    raise RuntimeError(message)


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def save(path, value):
    temporary = path.with_name(path.name + '.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def command(argv, **options):
    return subprocess.run(argv, check=True, timeout=options.pop('timeout', 600), **options)


def manifest():
    data = json.loads((BUNDLE / 'manifest.json').read_text())
    if data.get('schema') != 'keep.appliance.bundle/v1':
        fail('Unknown bundle manifest')
    for name, wanted in data['files'].items():
        relative = Path(name)
        path = BUNDLE / relative
        if relative.is_absolute() or '..' in relative.parts or path.is_symlink() or not path.is_file():
            fail('Invalid bundle input: ' + name)
        if digest(path) != wanted:
            fail('Bundle checksum mismatch: ' + name)
    return data


def prerequisites():
    if sys.platform != 'linux' or platform.machine() not in ('x86_64', 'amd64'):
        fail('This package requires a Linux x64 QEMU/KVM host; use the hosted demo on other hosts')
    if os.getuid() == 0:
        fail('Run the appliance as an unprivileged owner with existing KVM access')
    for tool in ('qemu-system-x86_64', 'qemu-img', 'ssh', 'ssh-keygen'):
        if not shutil.which(tool):
            fail('Missing host prerequisite: ' + tool + '; the launcher installs nothing')
    if not os.access('/dev/kvm', os.R_OK | os.W_OK):
        fail('Existing read/write KVM access is required; ask the host operator or use the hosted demo')
    help_text = command(['qemu-system-x86_64', '-machine', 'help'], capture_output=True, text=True).stdout
    if not any(line.split() and line.split()[0] == 'pc-q35-8.2' for line in help_text.splitlines()):
        fail('QEMU pc-q35-8.2 machine is unavailable')


def port_available(port):
    if not 1024 <= port <= 65535:
        fail('Choose a port from1024..65535')
    with socket.socket() as listener:
        try:
            listener.bind(('127.0.0.1', port))
        except OSError:
            fail('Chosen loopback port is occupied: ' + str(port))


def private_directory(raw, create=False):
    path = Path(raw).absolute()
    if path.is_symlink():
        fail('Instance directory cannot be a symlink')
    if not path.exists() and create:
        path.mkdir(mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        fail('Instance directory must be private mode0700 and owned by this user')
    return path.resolve()


@contextlib.contextmanager
def instance(raw, create=False):
    path = private_directory(raw, create)
    fd = os.open(path / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail('An appliance control operation is active; retained state is unchanged')
        record = path / 'instance.json'
        if record.exists():
            if record.is_symlink():
                fail('Invalid instance record')
            data = json.loads(record.read_text())
            if data.get('schema') != SCHEMA or data.get('bundle') != str(BUNDLE):
                fail('Unknown instance or another bundle; inspect retained state')
        elif create and set(p.name for p in path.iterdir()) == {'.lock'}:
            data = {'schema': SCHEMA, 'id': str(uuid.uuid4()), 'bundle': str(BUNDLE), 'stage': 'new'}
            save(record, data)
        else:
            fail('Existing directory has unknown state; choose a new private directory')
        yield path, data
    finally:
        os.close(fd)


def identity(pid):
    proc = Path('/proc') / str(pid)
    text = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    return {'pid': pid, 'start': text[19], 'uid': proc.stat().st_uid,
            'argvSha256': hashlib.sha256((proc / 'cmdline').read_bytes()).hexdigest()}


def alive(record):
    if not record:
        return False
    try:
        now = identity(record['pid'])
    except (FileNotFoundError, ProcessLookupError):
        return False
    state = (Path('/proc') / str(record['pid']) / 'stat').read_text().rsplit(')', 1)[1].split()[0]
    if state == 'Z' and now['start'] == record['start'] and now['uid'] == record['uid']:
        return False
    if now != record or now['uid'] != os.getuid():
        fail('Process identity changed; no signal sent; inspect the retained instance record')
    # A zombie has finished its work and must not be treated as a live service.
    return True


def spawn_owned(argv, log):
    executable = shutil.which(argv[0])
    if executable is None:
        fail('Missing launch executable: ' + argv[0])
    argv = [executable, *argv[1:]]
    with open(log, 'ab', buffering=0) as stream:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stream, stderr=stream,
                                 env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, start_new_session=True)
    return identity(child.pid)


def refuse_pending(data):
    pending = [name for name, record in data.get('dispatches', {}).items() if record['state'] == 'intent']
    if pending or data.get('stage') == 'initializing':
        fail('Unresolved appliance dispatch: ' + ','.join(pending or ['initialization']) + '; inspect retained state; no replacement or reset')


def dispatch_owned(path, data, name, argv, log):
    refuse_pending(data)
    data.setdefault('dispatches', {})[name] = {'state': 'intent', 'id': str(uuid.uuid4())}
    save(path / 'instance.json', data)
    # A crash before this confirmed handle leaves durable intent. Stop/retry may
    # not turn an unknown child into permission to launch a replacement.
    record = spawn_owned(argv, log)
    data[name] = record
    data['dispatches'][name]['state'] = 'confirmed'
    save(path / 'instance.json', data)
    return record


def terminate(record):
    if alive(record):
        os.kill(record['pid'], signal.SIGTERM)
        deadline = time.monotonic() + 30
        while alive(record) and time.monotonic() < deadline:
            time.sleep(0.1)
        if alive(record):
            fail('Owned process did not stop; state retained, no forced kill or reset')


def ssh_options(path, data):
    return ['ssh', '-F', '/dev/null', '-i', str(path / 'owner-key'), '-o', 'IdentitiesOnly=yes',
            '-o', 'ForwardAgent=no', '-o', 'ControlMaster=no', '-o', 'PermitLocalCommand=no',
            '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'UserKnownHostsFile=' + str(path / 'known-hosts'),
            '-o', 'StrictHostKeyChecking=' + ('yes' if (path / 'known-hosts').exists() else 'accept-new'),
            '-p', str(data['sshPort'])]


def guest(path, data, argv, **options):
    if not alive(data.get('qemu')):
        fail('Owned guest is not running')
    verify_overlay(path, data)
    return command(ssh_options(path, data) + ['keep@127.0.0.1', shlex.join(argv)], **options)


def seed_server(raw):
    path = private_directory(raw)
    data = json.loads((path / 'instance.json').read_text())
    public_key = (path / 'owner-key.pub').read_text().strip()
    config = {'users': [{'name': 'keep', 'shell': '/bin/bash', 'lock_passwd': True,
                         'ssh_authorized_keys': [public_key]}], 'ssh_pwauth': False, 'disable_root': True}
    payloads = {'/user-data': '#cloud-config\n' + json.dumps(config) + '\n',
                '/meta-data': 'instance-id: keep-' + data['id'] + '\nlocal-hostname: keep-reviewer\n'}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = payloads.get(self.path)
            if body is None:
                self.send_error(404)
                return
            encoded = body.encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
    save(path / 'seed-ready.json', {'port': server.server_port})
    server.serve_forever()


def qemu_value(path):
    return str(path).replace(',', ',,')


def verify_overlay(path, data):
    info = (path / 'instance.qcow2').stat()
    if data.get('overlay') != {'device': info.st_dev, 'inode': info.st_ino}:
        fail('Owned overlay identity changed; inspect retained state')


def start(path, data, port, ssh_port):
    refuse_pending(data)
    prerequisites()
    frozen = manifest()
    if alive(data.get('qemu')) or alive(data.get('seed')) or alive(data.get('tunnel')):
        fail('An owned appliance resource is still running; use status/stop')
    if data['stage'] not in ('new', 'stopped'):
        fail('Previous startup/shutdown is unresolved; inspect retained state before recovery')
    port_available(port); port_available(ssh_port)
    if port == ssh_port:
        fail('Console and SSH ports must differ')
    qmp = path / 'qmp.sock'
    if len(os.fsencode(qmp)) > 103:
        fail('Instance path is too long for a private QMP socket; choose a shorter path')
    if data['stage'] == 'new':
        if shutil.disk_usage(path).free < 8 * 1024 ** 3:
            fail('At least8GiB free host storage is required for this profile')
        data['stage'] = 'initializing'
        save(path / 'instance.json', data)
        command(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(path / 'owner-key')])
        command(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(BUNDLE / 'keep.qcow2'), str(path / 'instance.qcow2')], capture_output=True)
        info = (path / 'instance.qcow2').stat()
        data['overlay'] = {'device': info.st_dev, 'inode': info.st_ino}
        data['imageSha256'] = frozen['files']['keep.qcow2']
        data['stage'] = 'prepared'
        save(path / 'instance.json', data)
    elif data['imageSha256'] != frozen['files']['keep.qcow2']:
        fail('Bundle image changed; existing instance is retained')
    verify_overlay(path, data)
    for name in ('seed-ready.json', 'qmp.sock'):
        target = path / name
        if target.exists():
            target.unlink()  # Prior resources are all confirmed stopped above.
    data.update({'stage': 'starting', 'port': port, 'sshPort': ssh_port})
    save(path / 'instance.json', data)
    dispatch_owned(path, data, 'seed', [sys.executable, str(Path(__file__).resolve()), '_seed', str(path)], path / 'seed.log')
    deadline = time.monotonic() + 600
    while not (path / 'seed-ready.json').exists():
        if not alive(data['seed']) or time.monotonic() >= deadline:
            fail('Seed startup failed; inspect retained logs and use stop')
        time.sleep(0.1)
    seed_port = json.loads((path / 'seed-ready.json').read_text())['port']
    args = ['qemu-system-x86_64', '-name', 'keep-' + data['id'], '-machine', 'pc-q35-8.2,accel=kvm',
            '-cpu', 'host', '-smp', '2', '-m', '2048', '-display', 'none', '-monitor', 'none',
            '-serial', 'file:' + qemu_value(path / 'serial.log'),
            '-qmp', 'unix:' + qemu_value(qmp) + ',server=on,wait=off',
            '-drive', 'file=' + qemu_value(path / 'instance.qcow2') + ',if=virtio,format=qcow2',
            '-netdev', 'user,id=net0,hostfwd=tcp:127.0.0.1:' + str(ssh_port) + '-:22',
            '-device', 'virtio-net-pci,netdev=net0', '-smbios', 'type=1,serial=ds=nocloud;s=http://10.0.2.2:' + str(seed_port) + '/']
    dispatch_owned(path, data, 'qemu', args, path / 'qemu.log')
    while True:
        try:
            guest(path, data, ['test', '-f', '/opt/keep/appliance-ready'], capture_output=True, timeout=10)
            break
        except subprocess.CalledProcessError:
            if not alive(data['qemu']) or time.monotonic() >= deadline:
                fail('Guest startup did not confirm readiness; inspect retained logs and use stop')
            time.sleep(1)
    data['stage'] = 'running'
    save(path / 'instance.json', data)
    return {'status': 'guest-ready', 'instance': str(path), 'sampleStarted': False,
            'next': 'sample-start', 'credentialsBaked': False}


def tunnel(path, data):
    refuse_pending(data)
    if alive(data.get('tunnel')):
        return
    port_available(data['port'])
    args = ssh_options(path, data) + ['-N', '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=15',
            '-o', 'ServerAliveCountMax=2', '-L', '127.0.0.1:{0}:127.0.0.1:{0}'.format(data['port']), 'keep@127.0.0.1']
    dispatch_owned(path, data, 'tunnel', args, path / 'tunnel.log')


def sample(path, data, action):
    refuse_pending(data)
    verify_overlay(path, data)
    result = guest(path, data, ['keep-reviewer', action, str(data['port'])], capture_output=True, text=True)
    value = json.loads(result.stdout)
    if action == 'start':
        tunnel(path, data)
        deadline = time.monotonic() + 30
        url = 'http://127.0.0.1:' + str(data['port']) + '/console'
        while True:
            try:
                with urllib.request.urlopen(url, timeout=3) as response:
                    body = response.read().decode()
                if 'Instance credential' not in body or 'two scripted responses' not in body:
                    fail('Forwarded endpoint did not identify the sample console')
                break
            except OSError:
                if not alive(data['tunnel']) or time.monotonic() >= deadline:
                    fail('Owned SSH forward did not reach the console; inspect retained logs')
                time.sleep(0.1)
        value['checkedBrowserOrigin'] = url
    elif action == 'stop':
        terminate(data.get('tunnel'))
    return value


def qmp_powerdown(path):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(5)
        connection.connect(str(path / 'qmp.sock'))
        with connection.makefile('rwb', buffering=0) as stream:
            json.loads(stream.readline())
            for name in ('qmp_capabilities', 'system_powerdown'):
                stream.write((json.dumps({'execute': name}) + '\n').encode())
                while True:
                    result = json.loads(stream.readline())
                    if 'error' in result:
                        fail('QMP refused owned shutdown: ' + str(result['error']))
                    if 'return' in result:
                        break


def stop(path, data):
    refuse_pending(data)
    if data['stage'] == 'new':
        return {'status': 'guest-not-started', 'stateRetained': True, 'unresolved': []}
    unresolved = 'unknown'
    if alive(data.get('qemu')):
        verify_overlay(path, data)
        try:
            stopped = guest(path, data, ['keep-reviewer', 'stop', str(data['port'])], capture_output=True, text=True, timeout=40)
            unresolved = json.loads(stopped.stdout).get('unresolved', 'unknown')
        except subprocess.SubprocessError:
            pass
        qmp_powerdown(path)
        deadline = time.monotonic() + 30
        while alive(data['qemu']) and time.monotonic() < deadline:
            time.sleep(0.1)
        if alive(data['qemu']):
            fail('Guest shutdown not confirmed; retained state and own processes require inspection')
    terminate(data.get('tunnel')); terminate(data.get('seed'))
    data['stage'] = 'stopped'
    save(path / 'instance.json', data)
    return {'status': 'guest-stopped', 'stateRetained': True, 'unresolved': unresolved}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['check', 'start', 'status', 'stop', 'sample-start', 'sample-stop', 'sample-status', 'credential', 'shell', 'run', '_seed'])
    parser.add_argument('state', nargs='?')
    parser.add_argument('--port', type=int, default=7788)
    parser.add_argument('--ssh-port', type=int, default=2222)
    args, rest = parser.parse_known_args()
    if args.action == 'check':
        if rest: fail('Unexpected arguments')
        prerequisites(); print(json.dumps({'status': 'prerequisites-present', 'bundle': manifest()})); return
    if not args.state: fail('Private instance directory is required')
    if args.action == '_seed': seed_server(args.state); return
    if rest and args.action != 'run': fail('Unexpected arguments')
    with instance(args.state, create=args.action == 'start') as (path, data):
        if args.action == 'start': value = start(path, data, args.port, args.ssh_port)
        elif args.action == 'stop': value = stop(path, data)
        elif args.action == 'status':
            value = {'stage': data['stage'], 'guestRunning': alive(data.get('qemu')), 'tunnelRunning': alive(data.get('tunnel')), 'stateRetained': True,
                     'unresolvedDispatches': [name for name, record in data.get('dispatches', {}).items() if record['state'] == 'intent']}
        elif args.action.startswith('sample-'): value = sample(path, data, args.action[7:])
        elif args.action == 'credential':
            guest(path, data, ['cat', '/home/keep/reviewer-sample/invitation-token']); return
        elif args.action == 'shell':
            command(ssh_options(path, data) + ['-t', 'keep@127.0.0.1'], timeout=None); return
        else:
            if rest and rest[0] == '--': rest = rest[1:]
            if not rest: fail('run requires a guest command after --')
            guest(path, data, rest); return
        print(json.dumps(value))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print('Appliance refused: ' + str(error) + '\nRetained instance state was not reset.', file=sys.stderr)
        sys.exit(1)
