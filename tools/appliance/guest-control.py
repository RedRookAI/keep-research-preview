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


def write_state(data):
    path = ROOT / 'control.new'
    with path.open('x') as stream:
        json.dump(data, stream)
        stream.flush(); os.fsync(stream.fileno())
    path.replace(ROOT / 'control.json')


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
        data = json.loads(state_file.read_text()) if state_file.exists() else {'stage': 'new'}
        running = data.get('stage') != 'stopped' and alive(data.get('process'))
        if action == 'start' and not running:
            if data.get('stage') == 'starting':
                raise RuntimeError('Previous sample startup is unresolved; inspect retained logs')
            log = open(ROOT / 'sample.log', 'ab', buffering=0)
            child = subprocess.Popen([NODE, ENTRY, str(SAMPLE), str(port)], stdin=subprocess.DEVNULL,
                stdout=log, stderr=log, start_new_session=True,
                env={'PATH': '/opt/keep/node-v22.23.4-linux-x64/bin:/usr/bin:/bin', 'HOME': str(Path.home()), 'LANG': 'C.UTF-8'})
            log.close()
            data = {'stage': 'starting', 'process': identity(child.pid), 'port': port,
                    'eventsBeforeStart': len(events())}
            write_state(data)
            deadline = time.monotonic() + 30
            while True:
                fresh = events()[data['eventsBeforeStart']:]
                if fresh and fresh[-1]['event'] == 'sample-ready':
                    data['stage'] = 'running'; write_state(data); running = True; break
                if not alive(data['process']) or time.monotonic() >= deadline:
                    raise RuntimeError('Sample startup did not confirm readiness; inspect retained sample.log')
                time.sleep(0.1)
        elif action == 'stop':
            if running:
                os.kill(data['process']['pid'], signal.SIGTERM)
                deadline = time.monotonic() + 30
                while alive(data['process']) and time.monotonic() < deadline:
                    time.sleep(0.1)
                if alive(data['process']):
                    raise RuntimeError('Sample stop not confirmed; state retained without forced termination')
            data['stage'] = 'stopped'; write_state(data); running = False
        history = events()
        last_ready = next((value for value in reversed(history) if value['event'] == 'sample-ready'), None)
        last_stop = next((value for value in reversed(history) if value['event'] == 'sample-stopped'), None)
        print(json.dumps({'status': 'running' if running else 'stopped', 'stateRetained': SAMPLE.exists(),
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
