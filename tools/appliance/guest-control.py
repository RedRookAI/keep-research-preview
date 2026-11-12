#!/usr/bin/env python3
"""Private controls for this guest's single account-free reviewer sample."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path.home() / '.keep-reviewer-control'
SAMPLE = Path.home() / 'reviewer-sample'
NODE = '/opt/keep/node-v22.23.4-linux-x64/bin/node'
ENTRY = '/opt/keep/runtime/tools/reviewer_local_sample.mjs'


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def identity(pid):
    p = Path('/proc') / str(pid)
    return {'pid': pid, 'bootId': boot_id(), 'start': (p / 'stat').read_text().rsplit(')', 1)[1].split()[19],
            'uid': p.stat().st_uid, 'argvSha256': hashlib.sha256((p / 'cmdline').read_bytes()).hexdigest()}


def alive(record):
    if not record or record['bootId'] != boot_id():
        return False
    try:
        now = identity(record['pid'])
    except FileNotFoundError:
        return False
    if now['start'] != record['start']:
        raise RuntimeError('PID was reused; no signal or new sample dispatched; inspect private control state')
    state = (Path('/proc') / str(record['pid']) / 'stat').read_text().rsplit(')', 1)[1].split()[0]
    if state == 'Z':
        return False
    if now != record or now['uid'] != os.getuid():
        raise RuntimeError('Sample process identity changed; retained state requires inspection')
    return True


def events():
    path = ROOT / 'sample.log'
    if not path.exists():
        return []
    result = []
    for line in path.read_text().splitlines():
        try:
            value = json.loads(line)
            if isinstance(value, dict) and value.get('event') in ('sample-ready', 'sample-stopped'):
                result.append(value)
        except ValueError:
            pass
    return result


def read_stop_state(pid):
    proc = Path('/proc') / str(pid)
    fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    return {'uid': proc.stat().st_uid, 'start': fields[19], 'state': fields[0]}


def awaiting_exit(record):
    """Observe exit after one fully admitted signal; do not read dying argv."""
    try:
        now = read_stop_state(record['pid'])
    except (FileNotFoundError, ProcessLookupError):
        return False
    if now['uid'] != record['uid'] or now['start'] != record['start']:
        raise RuntimeError('Process identity changed during stop; outcome remains unresolved')
    return now['state'] not in ('Z', 'X')


def write_state(data):
    path = ROOT / 'control.new'
    with path.open('x') as stream:
        json.dump(data, stream)
        stream.flush(); os.fsync(stream.fileno())
    path.replace(ROOT / 'control.json')
    directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def start_sample(data, port):
    if data.get('stage') == 'starting':
        raise RuntimeError('Previous sample dispatch is unresolved; inspect retained state; no replacement')
    baseline = len(events())
    data.update({'stage': 'starting', 'dispatchId': str(uuid.uuid4()), 'port': port, 'eventsBeforeStart': baseline})
    data.pop('process', None)
    write_state(data)  # Durable intent precedes Popen, including the handle gap.
    with open(ROOT / 'sample.log', 'ab', buffering=0) as log:
        child = subprocess.Popen([NODE, ENTRY, str(SAMPLE), str(port)], stdin=subprocess.DEVNULL,
            stdout=log, stderr=log, start_new_session=True,
            env={'PATH': '/opt/keep/node-v22.23.4-linux-x64/bin:/usr/bin:/bin', 'HOME': str(Path.home()), 'LANG': 'C.UTF-8'})
    data['process'] = identity(child.pid)
    write_state(data)
    deadline = time.monotonic() + 30
    while True:
        fresh = events()[baseline:]
        if fresh and fresh[-1]['event'] == 'sample-ready':
            data['stage'] = 'running'; write_state(data); return
        if not alive(data['process']) or time.monotonic() >= deadline:
            raise RuntimeError('Sample startup did not confirm readiness; inspect retained sample.log')
        time.sleep(0.1)


def stop_sample(data):
    if data.get('stage') == 'starting' and not data.get('process'):
        raise RuntimeError('Unresolved sample dispatch has no confirmed handle; stop cannot clear it')
    if data.get('stage') != 'stopped' and alive(data.get('process')):
        os.kill(data['process']['pid'], signal.SIGTERM)
        deadline = time.monotonic() + 30
        while awaiting_exit(data['process']) and time.monotonic() < deadline:
            time.sleep(0.1)
        if awaiting_exit(data['process']):
            raise RuntimeError('Sample stop not confirmed; state retained without forced termination')
    data['stage'] = 'stopped'; write_state(data)


def main():
    if os.getuid() == 0:
        raise RuntimeError('Sample must run as the unprivileged guest owner')
    os.umask(0o077)
    ROOT.mkdir(mode=0o700, exist_ok=True)
    st = ROOT.lstat()
    if ROOT.is_symlink() or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise RuntimeError('Sample control directory is not private and owned')
    fd = os.open(ROOT / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        action = sys.argv[1] if len(sys.argv) > 1 else 'status'
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 7788
        if action not in ('start', 'status', 'stop') or not 1024 <= port <= 65535:
            raise RuntimeError('Expected start/status/stop and console port1024..65535')
        state_file = ROOT / 'control.json'
        data = json.loads(state_file.read_text()) if state_file.exists() else {'schema': 'keep.appliance.sample-control/v1', 'stage': 'new'}
        if data.get('schema') != 'keep.appliance.sample-control/v1' or data.get('stage') not in ('new', 'starting', 'running', 'stopped'):
            raise RuntimeError('Unknown sample control state; existing work is retained')
        running = data.get('stage') != 'stopped' and alive(data.get('process'))
        if action == 'start':
            if data['stage'] == 'starting':
                raise RuntimeError('Previous sample dispatch is unresolved; inspect retained state')
            if not running: start_sample(data, port); running = True
        elif action == 'stop':
            stop_sample(data); running = False
        history = events()
        last_ready = next((value for value in reversed(history) if value['event'] == 'sample-ready'), None)
        last_stop = next((value for value in reversed(history) if value['event'] == 'sample-stopped'), None)
        print(json.dumps({'status': data['stage'] if data['stage'] == 'starting' else ('running' if running else 'stopped'), 'stateRetained': SAMPLE.exists(),
            'sample': last_ready, 'unresolved': (last_stop or {}).get('unresolved', [] if not history else 'unknown'),
            'scripted': True, 'paidCalls': 0}))
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError) as error:
        print('Sample control refused: ' + str(error), file=sys.stderr)
        sys.exit(1)
