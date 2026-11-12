#!/usr/bin/env python3
"""Build only inside the approved disposable x64 CI fixture, after source freeze."""
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
BASE_URL = 'https://cloud.debian.org/images/cloud/trixie/20261111-2659'
BASE_NAME = 'debian-13-generic-amd64-20261111-2659.qcow2'
BASE_SHA = 'ec8c175e39d59e711798c3a2f22ba11b9aee9bca1887c7e505a800aeffd5d7616099bd0e9fad869efba96100fe09d2c8b49d6d7001d501f0056c556bdc25b605'
RELEASE = 'https://github.com/RedRookAI/keep-research-preview/releases/download/keep-preview-2026-11-11.2'
ARCHIVE_SHA = '7b22762a48a0f6e1e26db342b51ef211035db0cf1b88619a720324b3ef5f3fca'
NODE_SHA = '1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce'
HELPER_SHA = 'e96e817b17de74e75f9680755a700f16c9f59917a264c499175da704651bd41f'
ENGINE_SHA = 'fdd9a1a3e86fc2213e4c0bd9c9b278080f38d756a5256e3217092a30e48d98c1'


def run(argv, **kwargs):
    print('KC111_STEP=' + json.dumps(argv), flush=True)
    return subprocess.run(argv, check=True, **kwargs)


def sha(path, algorithm='sha256'):
    h = hashlib.new(algorithm)
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''): h.update(block)
    return h.hexdigest()


def fetch(url, path, wanted=None, algorithm='sha256'):
    run(['curl', '--fail', '--location', '--silent', '--show-error', url, '-o', str(path)])
    if wanted and sha(path, algorithm) != wanted:
        raise RuntimeError('Public input checksum mismatch: ' + path.name)


def extract_baseline(archive, destination):
    # The frozen archive is SHA-verified before this call. Preserve its recorded
    # readonly/executable modes even under the builder's private umask077.
    run(['tar', '--same-permissions', '-xzf', str(archive), '-C', str(destination)])


def verify_carried_native(artifact, expected):
    actual_sha = sha(artifact)
    actual_mode = artifact.stat().st_mode & 0o777
    expected_mode = int(expected['modeOctal'], 8)
    if actual_sha != expected['sha256'] or actual_mode != expected_mode:
        raise RuntimeError('Carried native identity/mode mismatch: ' + expected['name']
            + ' expected_sha256=' + expected['sha256'] + ' actual_sha256=' + actual_sha
            + ' expected_mode=' + oct(expected_mode) + ' actual_mode=' + oct(actual_mode))


def background_freeze(script='/root/kc111-freeze.sh', serial_device='/dev/ttyS0'):
    # /dev/console can select VGA even when kernel messages also reach serial.
    # This profile explicitly captures QEMU's first serial port, ttyS0.
    return ['bash', '-c', 'nohup setsid ' + shlex.quote(script) + ' >' + shlex.quote(str(serial_device)) + ' 2>&1 </dev/null &']


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or platform.machine() != 'x86_64' or os.getuid() == 0:
        raise RuntimeError('Use the approved nonroot disposable CI x64 fixture only')
    source = run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    if source != os.environ['GITHUB_SHA']:
        raise RuntimeError('Checkout differs from frozen CI source')
    for path, wanted in [('native', 'bbc14279d4d5ebb5f105371b79a0f36ea0e18576'), ('tools/build_native_transport.mjs', '8356e8600ce60ee3aa690dcd69daf9f1509755c0')]:
        actual = run(['git', 'rev-parse', 'HEAD:' + path], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        if actual != wanted: raise RuntimeError('Native build inputs changed; carried bytes require review: ' + path)
    os.umask(0o077)
    work = Path(tempfile.mkdtemp(prefix='kc111-builder-', dir=os.environ['GITHUB_WORKSPACE']))
    payload = work / 'payload'; payload.mkdir()
    output = ROOT / 'appliance-output'; output.mkdir()
    version = json.loads((ROOT / 'package.json').read_text())['version']
    contract_code = "const m=await import('./dist/src/review/reviewer_sample.js');if(!m.SAMPLE_CONTRACT||!m.SAMPLE_NOTICE)throw new Error('Frozen guided sample contract required');console.log(JSON.stringify({...m.SAMPLE_CONTRACT,notice:m.SAMPLE_NOTICE}));"
    sample_contract = json.loads(run(['node', '--input-type=module', '-e', contract_code], cwd=ROOT, capture_output=True, text=True).stdout)
    bundle = work / ('keep-reviewer-' + version + '-linux-x64'); bundle.mkdir()
    fetch(RELEASE + '/keep-combined-0.0.21-preview.1-linux-x64.tar.gz', work / 'baseline.tgz', ARCHIVE_SHA)
    extract_baseline(work / 'baseline.tgz', work)
    runtime = work / 'keep-0.0.21-preview.1'
    metadata_path = work / 'baseline.json'
    fetch(RELEASE + '/combined-preview-2026-11-11.2.json', metadata_path, '960485c2f2e2a6d469789c849f7adf56ebd7a2e727dac5e42a9edcfa9f41bcd0')
    metadata = json.loads(metadata_path.read_text())
    for item in metadata['nativeRelease']['artifacts']:
        artifact = runtime / 'dist/native/linux-x64' / item['name']
        verify_carried_native(artifact, item)
    shutil.rmtree(runtime / 'dist/src')
    shutil.copytree(ROOT / 'dist/src', runtime / 'dist/src')
    for name in ('src', 'docs', 'tools', 'bin'):
        if (runtime / name).exists(): shutil.rmtree(runtime / name)
        shutil.copytree(ROOT / name, runtime / name, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    for name in ('package.json', 'package-lock.json', 'README.md', 'WORKFLOW.md', 'SECURITY.md', 'LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.txt'):
        shutil.copy2(ROOT / name, runtime / name)
    shutil.rmtree(runtime / 'integrations/openclaw')
    (runtime / 'integrations/openclaw').mkdir()
    shutil.copy2(ROOT / 'integrations/openclaw/README.md', runtime / 'integrations/openclaw/README.md')
    run(['npm', 'pack', '--ignore-scripts', '--pack-destination', str(runtime / 'integrations/openclaw')], cwd=ROOT / 'integrations/openclaw')
    with open(runtime / 'source-support.tar.gz', 'wb') as stream:
        run(['git', 'archive', '--format=tar.gz', 'HEAD'], cwd=ROOT, stdout=stream)
    if sha(runtime / 'engines/codex-generation.2/bin/codex') != ENGINE_SHA:
        raise RuntimeError('Engine changed')
    run(['tar', '-czf', str(payload / 'runtime.tgz'), '-C', str(runtime), '.'])
    fetch('https://nodejs.org/dist/v22.23.4/node-v22.23.4-linux-x64.tar.xz', payload / 'node.tar.xz', NODE_SHA)
    run(['docker', 'build', '--file', 'tools/bubblewrap/Dockerfile', '--tag', 'kc111-helper:' + os.environ['GITHUB_RUN_ID'], '.'], cwd=ROOT)
    container = run(['docker', 'create', 'kc111-helper:' + os.environ['GITHUB_RUN_ID']], capture_output=True, text=True).stdout.strip()
    try:
        run(['docker', 'cp', container + ':/opt/keep/bubblewrap/0.13.0/bwrap', str(payload / 'bwrap')])
        run(['docker', 'cp', container + ':/build/build-packages.txt', str(bundle / 'helper-build-packages.txt')])
    finally: run(['docker', 'rm', container])
    if sha(payload / 'bwrap') != HELPER_SHA: raise RuntimeError('Helper identity changed')
    shutil.copy2(ROOT / 'tools/appliance/guest-control.py', payload / 'guest-control.py')
    # Public build provenance only. No authorized key or account is supplied to the build guest.
    components = {'schema': 'keep.appliance.image-build/v1', 'source': source, 'version': version,
                  'baseUrl': BASE_URL + '/' + BASE_NAME, 'baseSha512': BASE_SHA,
                  'archiveBaselineSha256': ARCHIVE_SHA, 'nodeArchiveSha256': NODE_SHA,
                  'helperSha256': HELPER_SHA, 'engineSha256': ENGINE_SHA,
                  'nativeSourceTree': metadata['source']['nativeTree'], 'nativeArtifacts': metadata['nativeRelease']['artifacts']}
    (payload / 'image-build.json').write_text(json.dumps(components, indent=2) + '\n')
    receipt_path = work / 'guest-receipt.json'

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs): super().__init__(*args, directory=str(payload), **kwargs)
        def do_POST(self):
            size = int(self.headers.get('Content-Length', '0'))
            if self.path != '/receipt' or size > 1024 * 1024: self.send_error(400); return
            value = json.loads(self.rfile.read(size))
            if value.get('source') != source: self.send_error(400); return
            receipt_path.write_text(json.dumps(value, indent=2) + '\n')
            self.send_response(200); self.end_headers()

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_port
    provision = '#!/bin/bash\nset -euo pipefail\numask 022\nmkdir -p /opt/keep/runtime /opt/keep/bubblewrap/0.13.0 /opt/keep/downloads\ncd /opt/keep/downloads\n'
    for name in ('runtime.tgz', 'node.tar.xz', 'bwrap', 'guest-control.py', 'image-build.json'):
        provision += f"curl --fail --silent --show-error http://10.0.2.2:{port}/{name} -o {name}\nprintf '%s\\n' '{sha(payload / name)}  {name}' | sha256sum -c -\n"
    provision += '''tar -xzf runtime.tgz -C /opt/keep/runtime
tar -xJf node.tar.xz -C /opt/keep
install -m 0755 bwrap /opt/keep/bubblewrap/0.13.0/bwrap
install -m 0755 guest-control.py /usr/local/bin/keep-reviewer
install -m 0644 image-build.json /opt/keep/image-build.json
printf '%s\\n' '#!/bin/sh' 'exec /opt/keep/node-v22.23.4-linux-x64/bin/node /opt/keep/runtime/dist/src/main.js "$@"' > /usr/local/bin/keep
printf '%s\\n' '#!/bin/sh' 'exec /opt/keep/runtime/engines/codex-generation.2/bin/codex "$@"' > /usr/local/bin/keep-engine
chmod 0755 /usr/local/bin/keep /usr/local/bin/keep-engine
apt-get update -qq
apt-get install -y -qq --no-install-recommends git=1:2.47.3-0+deb13u1
dpkg-query -W > /opt/keep/guest-packages.txt
chown -R root:root /opt/keep
chmod -R go-w /opt/keep
touch /opt/keep/appliance-ready
'''
    provision += f"curl --fail --silent --show-error -X POST --data-binary @/opt/keep/image-build.json http://10.0.2.2:{port}/receipt\n"
    freeze = '''#!/bin/bash
set -euo pipefail
cloud-init status --wait
cloud-init clean --logs --seed --machine-id --configs ssh_config
rm -f /etc/ssh/ssh_host_* /var/lib/systemd/random-seed
rm -rf /home/keep /root/.ssh /opt/keep/downloads
install -d -o keep -g keep -m 0700 /home/keep
rm -f /root/.bash_history /root/kc111-provision.sh /root/kc111-freeze.sh
find /var/log -type f -exec truncate -s 0 {} +
sync
fstrim -av
echo KC111_IMAGE_SANITIZED
systemctl poweroff
'''
    config = {'users': [{'name': 'keep', 'shell': '/bin/bash', 'lock_passwd': True}], 'ssh_pwauth': False, 'disable_root': True,
              'write_files': [{'path': '/root/kc111-provision.sh', 'permissions': '0700', 'content': provision},
                              {'path': '/root/kc111-freeze.sh', 'permissions': '0700', 'content': freeze}],
              'runcmd': [['bash', '/root/kc111-provision.sh'], background_freeze()]}
    (payload / 'user-data').write_text('#cloud-config\n' + json.dumps(config) + '\n')
    (payload / 'meta-data').write_text('instance-id: kc111-build-' + os.environ['GITHUB_RUN_ID'] + '\nlocal-hostname: keep-image-builder\n')
    base = work / BASE_NAME
    fetch(BASE_URL + '/' + BASE_NAME, base, BASE_SHA, 'sha512'); base.chmod(0o444)
    overlay = work / 'build.qcow2'
    run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(base), str(overlay), '8G'])
    # Inherited process-only KVM group; this process and QEMU both stay nonroot.
    args = ['qemu-system-x86_64', '-machine', 'pc-q35-8.2,accel=kvm', '-cpu', 'host', '-smp', '2', '-m', '2048',
            '-display', 'none', '-monitor', 'none', '-serial', 'file:' + str(work / 'serial.log'),
            '-drive', 'file=' + str(overlay) + ',if=virtio,format=qcow2,discard=unmap,detect-zeroes=unmap',
            '-netdev', 'user,id=net0', '-device', 'virtio-net-pci,netdev=net0',
            '-smbios', 'type=1,serial=ds=nocloud;s=http://10.0.2.2:' + str(port) + '/']
    with open(work / 'qemu.log', 'wb') as log:
        vm = subprocess.Popen(args, stdout=log, stderr=log)
    try:
        vm.wait(timeout=600)
        if vm.returncode != 0: raise RuntimeError('Image provisioning guest failed')
        serial = (work / 'serial.log').read_text(errors='replace')
        if 'KC111_IMAGE_SANITIZED' not in serial or not receipt_path.exists():
            raise RuntimeError('Image sanitization/provisioning not confirmed: serial_marker='
                + str('KC111_IMAGE_SANITIZED' in serial) + ' source_receipt=' + str(receipt_path.exists()))
    finally:
        server.shutdown(); server.server_close()
        if vm.poll() is None: vm.terminate(); vm.wait(timeout=30)
        print((work / 'serial.log').read_text(errors='replace')[-24000:], flush=True)
        print((work / 'qemu.log').read_text(errors='replace'), flush=True)
    # Flatten the completed guest into a standalone base, then freeze these bytes.
    run(['qemu-img', 'convert', '-O', 'qcow2', str(overlay), str(bundle / 'keep.qcow2')])
    run(['qemu-img', 'check', str(bundle / 'keep.qcow2')])
    disk_info = json.loads(run(['qemu-img', 'info', '--output=json', str(bundle / 'keep.qcow2')], capture_output=True, text=True).stdout)
    if disk_info.get('backing-filename'): raise RuntimeError('Candidate still depends on a developer backing file')
    shutil.copy2(ROOT / 'tools/appliance/keep-appliance.py', bundle / 'keep-appliance.py')
    shutil.copy2(ROOT / 'docs/reviewer-appliance.md', bundle / 'GUIDE.md')
    shutil.copy2(ROOT / 'tools/appliance/consumer.py', bundle / 'qualify.py')
    shutil.copy2(ROOT / 'LICENSE', bundle / 'LICENSE')
    shutil.copy2(ROOT / 'NOTICE', bundle / 'NOTICE')
    shutil.copy2(ROOT / 'THIRD_PARTY_NOTICES.txt', bundle / 'THIRD_PARTY_NOTICES.txt')
    shutil.copy2(receipt_path, bundle / 'image-build.json')
    manifest = {'schema': 'keep.appliance.bundle/v1', 'source': source, 'packageVersion': version,
                'profile': {'guest': 'Debian13 generic amd64 20261111-2659', 'machine': 'pc-q35-8.2', 'accelerator': 'kvm', 'vcpus': 2, 'ramMiB': 2048, 'diskVirtualBytes': disk_info['virtual-size']},
                'components': components, 'sampleContract': sample_contract,
                'qemuVersion': run(['qemu-system-x86_64', '--version'], capture_output=True, text=True).stdout.splitlines()[0],
                'files': {p.name: sha(p) for p in bundle.iterdir() if p.is_file()}, 'shippingCredentials': False}
    (bundle / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (bundle / 'SHA256SUMS').write_text(''.join(sha(p) + '  ' + p.name + '\n' for p in sorted(bundle.iterdir()) if p.is_file()))
    artifact = output / (bundle.name + '-' + source[:12] + '-' + os.environ['GITHUB_RUN_ID'] + '.tar.xz')
    run(['tar', '-cJf', str(artifact), '-C', str(work), bundle.name], env={**os.environ, 'XZ_OPT': '-T1 -6'})
    (output / 'SHA256SUMS').write_text(sha(artifact) + '  ' + artifact.name + '\n')
    receipt = {'schema': 'keep.appliance.candidate/v1', 'source': source, 'archive': artifact.name, 'sha256': sha(artifact), 'compressedBytes': artifact.stat().st_size,
               'imageSha256': manifest['files']['keep.qcow2'], 'imageBytes': (bundle / 'keep.qcow2').stat().st_size,
               'diskVirtualBytes': disk_info['virtual-size'], 'sourceFreezeRequired': True, 'consumerPassed': False}
    (output / 'candidate.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print('KC111_CANDIDATE_JSON=' + json.dumps(receipt), flush=True)


if __name__ == '__main__': main()
