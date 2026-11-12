#!/usr/bin/env bash
# Approved disposable GitHub x64 fixture only. No local/shared-host execution.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
test "${GITHUB_REF_NAME:-}" = work/kc110-profile-proof-2026-11-12
test "$(uname -m)" = x86_64
test "$(id -u)" != 0
umask 077
fixture=$(mktemp -d "$GITHUB_WORKSPACE/kc110-fixture.XXXXXX")
payload="$fixture/payload"
mkdir "$payload"
http_pid= qemu_pid= helper_container=
cleanup() {
  result=$?
  trap - EXIT
  if test -f "$fixture/qemu.pid"; then kill "$(cat "$fixture/qemu.pid")" 2>/dev/null || true; fi
  if test -n "$qemu_pid"; then wait "$qemu_pid" 2>/dev/null || true; fi
  if test -n "$http_pid"; then kill "$http_pid" 2>/dev/null || true; wait "$http_pid" 2>/dev/null || true; fi
  if test -n "$helper_container"; then docker rm "$helper_container" >/dev/null 2>&1 || true; fi
  if test "$result" != 0; then
    echo 'KC110_FIXTURE_FAILED: preserving actual diagnostics, no automatic retry or policy change'
    for log in qemu.log serial.log http.log ssh-readiness.log guest-provision.log proof.log; do
      if test -f "$fixture/$log"; then echo "KC110_LOG=$log"; tail -c 24000 "$fixture/$log"; fi
    done
  fi
  exit "$result"
}
trap cleanup EXIT
python3 - <<'PY'
import os,json,platform,pathlib
d={'schema':'keep.kc110-executed-fixture/v1','source':os.environ['GITHUB_SHA'],'runId':os.environ['GITHUB_RUN_ID'],
'host':{'osRelease':pathlib.Path('/etc/os-release').read_text(),'kernel':platform.release(),'machine':platform.machine(),
'uid':os.getuid(),'imageVersion':os.environ.get('ImageVersion'),'freeBytes':os.statvfs('.').f_bavail*os.statvfs('.').f_frsize},
'guestPolicyChanged':False,'sharedHostChanged':False,'guestBooted':False}
print('KC110_EXECUTED_FIXTURE_JSON='+json.dumps(d,separators=(',',':')))
assert d['host']['freeBytes'] > 12*1024**3, 'insufficient observed disk for approved fixture'
PY
command -v docker
command -v setpriv
test -c /dev/kvm
printf '%s\n' 'a317b76c36d96871effb743645147046c8f2dd00d9fa7eac29ea4f8cc994306f  tools/bubblewrap/Dockerfile' | sha256sum -c -
sudo apt-get update -qq
sudo apt-get install -y -qq --no-install-recommends qemu-system-x86 qemu-utils
qemu-system-x86_64 --version
qemu-img --version
qemu-system-x86_64 -machine help | awk '$1=="pc-q35-8.2" {found=1; print $0} END {if (!found) exit 1}'
sha256sum "$(command -v qemu-system-x86_64)" "$(command -v qemu-img)"
dpkg-query -W qemu-system-x86 qemu-system-common qemu-utils qemu-system-data

# Existing pinned build environment; ordinary build, no privileged container.
docker build --file tools/bubblewrap/Dockerfile --tag "kc110-bwrap:$GITHUB_RUN_ID" .
helper_container=$(docker create "kc110-bwrap:$GITHUB_RUN_ID")
docker cp "$helper_container:/opt/keep/bubblewrap/0.13.0/bwrap" "$payload/bwrap"
docker cp "$helper_container:/build/build-packages.txt" "$fixture/helper-build-packages.txt"
docker rm "$helper_container" >/dev/null
helper_container=
printf '%s\n' "e96e817b17de74e75f9680755a700f16c9f59917a264c499175da704651bd41f  $payload/bwrap" | sha256sum -c -
cat "$fixture/helper-build-packages.txt"

base=debian-13-generic-amd64-20261111-2659.qcow2
base_url=https://cloud.debian.org/images/cloud/trixie/20261111-2659
curl --fail --location --silent --show-error "$base_url/$base" -o "$fixture/$base"
printf '%s\n' "ec8c175e39d59e711798c3a2f22ba11b9aee9bca1887c7e505a800aeffd5d7616099bd0e9fad869efba96100fe09d2c8b49d6d7001d501f0056c556bdc25b605  $fixture/$base" | sha512sum -c -
curl --fail --location --silent --show-error "$base_url/SHA512SUMS" -o "$fixture/base-SHA512SUMS"
curl --fail --location --silent --show-error "$base_url/${base%.qcow2}.json" -o "$fixture/base.json"
curl --fail --location --silent --show-error https://github.com/RedRookAI/keep-research-preview/releases/download/keep-preview-2026-11-11.2/keep-combined-0.0.21-preview.1-linux-x64.tar.gz -o "$payload/keep.tar.gz"
printf '%s\n' "7b22762a48a0f6e1e26db342b51ef211035db0cf1b88619a720324b3ef5f3fca  $payload/keep.tar.gz" | sha256sum -c -
curl --fail --location --silent --show-error https://nodejs.org/dist/v22.23.4/SHASUMS256.txt -o "$fixture/node-SHASUMS256.txt"
curl --fail --location --silent --show-error https://nodejs.org/dist/v22.23.4/node-v22.23.4-linux-x64.tar.xz -o "$payload/node-v22.23.4-linux-x64.tar.xz"
node_archive_sha=$(awk '$2=="node-v22.23.4-linux-x64.tar.xz" {print $1}' "$fixture/node-SHASUMS256.txt")
test "${#node_archive_sha}" = 64
printf '%s\n' "$node_archive_sha  $payload/node-v22.23.4-linux-x64.tar.xz" | sha256sum -c -
cp .github/kc110/guest-proof.mjs "$payload/guest-proof.mjs"
ssh-keygen -q -t ed25519 -N '' -f "$fixture/guest-key"
qemu-img create -f qcow2 -F qcow2 -b "$fixture/$base" "$fixture/overlay.qcow2" 8G
qemu-img info --output=json "$fixture/overlay.qcow2"
export KC110_PAYLOAD="$payload" KC110_FIXTURE="$fixture" KC110_NODE_ARCHIVE_SHA="$node_archive_sha"
python3 - <<'PY'
import os,pathlib,json,hashlib
p=pathlib.Path(os.environ['KC110_PAYLOAD']); f=pathlib.Path(os.environ['KC110_FIXTURE'])
# Private loopback server is also reachable by the isolated slirp guest as 10.0.2.2.
provision='''#!/bin/bash
set -euo pipefail
umask 022
mkdir -p /opt/keep/runtime /opt/keep/bubblewrap/0.13.0 /opt/keep/downloads
cd /opt/keep/downloads
'''
for name in ['keep.tar.gz','node-v22.23.4-linux-x64.tar.xz','bwrap','guest-proof.mjs']:
 digest=hashlib.sha256((p/name).read_bytes()).hexdigest()
 provision+=f"curl --fail --silent --show-error http://10.0.2.2:8765/{name} -o {name}\nprintf '%s\\n' '{digest}  {name}' | sha256sum -c -\n"
provision+='''tar -xzf keep.tar.gz -C /opt/keep/runtime
tar -xJf node-v22.23.4-linux-x64.tar.xz -C /opt/keep
install -m 0755 bwrap /opt/keep/bubblewrap/0.13.0/bwrap
install -m 0644 guest-proof.mjs /opt/keep/guest-proof.mjs
chown -R root:root /opt/keep
chmod -R go-w /opt/keep
apt-get update -qq
apt-get install -y -qq --no-install-recommends git
uname -a
cat /etc/os-release
dpkg-query -W
for target in /opt/keep/node-v22.23.4-linux-x64/bin/node /opt/keep/runtime/keep-0.0.21-preview.1/engines/codex-generation.2/bin/codex /opt/keep/bubblewrap/0.13.0/bwrap; do
  sha256sum "$target"
  stat -c '%n %U %G %a' "$target"
  ldd "$target"
done
if test -r /sys/kernel/security/apparmor/profiles; then cat /sys/kernel/security/apparmor/profiles; fi
touch /opt/keep/provision.ok
'''
config={'users':[{'name':'keep','shell':'/bin/bash','lock_passwd':True,'ssh_authorized_keys':[(f/'guest-key.pub').read_text().strip()]}],
 'ssh_pwauth':False,'disable_root':True,'write_files':[{'path':'/root/kc110-provision.sh','permissions':'0700','content':provision}],
 'runcmd':[['bash','-c','/root/kc110-provision.sh > /opt/kc110-provision.log 2>&1 || touch /opt/keep/provision.failed']]}
(p/'user-data').write_text('#cloud-config\n'+json.dumps(config)+'\n')
(p/'meta-data').write_text('instance-id: kc110-'+os.environ['GITHUB_RUN_ID']+'\nlocal-hostname: kc110-proof\n')
print('KC110_INPUTS_JSON='+json.dumps({'baseSha512':'ec8c175e39d59e711798c3a2f22ba11b9aee9bca1887c7e505a800aeffd5d7616099bd0e9fad869efba96100fe09d2c8b49d6d7001d501f0056c556bdc25b605',
 'payloadSha256':{n:hashlib.sha256((p/n).read_bytes()).hexdigest() for n in ['keep.tar.gz','node-v22.23.4-linux-x64.tar.xz','bwrap','guest-proof.mjs']},
 'qemu':{'machine':'pc-q35-8.2','accelerator':'kvm','cpu':'host','vcpus':2,'ramMiB':2048,'overlayVirtualGiB':8,'sshBind':'127.0.0.1:2222','seedBind':'127.0.0.1:8765'}},separators=(',',':')))
PY
python3 -m http.server 8765 --bind 127.0.0.1 --directory "$payload" >"$fixture/http.log" 2>&1 &
http_pid=$!
runner_uid=$(id -u)
runner_gid=$(id -g)
kvm_gid=$(stat -c %g /dev/kvm)
runner_groups_with_kvm=$(printf '%s\n' "$(id -G | tr ' ' ',')",$kvm_gid | tr ',' '\n' | sort -un | paste -sd, -)
printf 'KC110_QEMU_IDENTITY=uid:%s gid:%s groups:%s\n' "$runner_uid" "$runner_gid" "$runner_groups_with_kvm"
sudo setpriv --reuid "$runner_uid" --regid "$runner_gid" --groups "$runner_groups_with_kvm" -- \
  bash -c 'printf "%s\n" "$$" > "$1"; shift; exec "$@"' kc110 "$fixture/qemu.pid" \
  qemu-system-x86_64 -machine pc-q35-8.2,accel=kvm -cpu host -smp 2 -m 2048 \
  -display none -monitor none -serial "file:$fixture/serial.log" \
  -drive "file=$fixture/overlay.qcow2,if=virtio,format=qcow2" \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net-pci,netdev=net0 \
  -smbios type=1,serial=ds=nocloud\;s=http://10.0.2.2:8765/ >"$fixture/qemu.log" 2>&1 &
qemu_pid=$!
export KC110_QEMU_PID="$qemu_pid"
# Readiness polling is a technical boot timeout, not a new autonomous task budget.
timeout 600 bash -c '
  until ssh -i "$KC110_FIXTURE/guest-key" -o UserKnownHostsFile="$KC110_FIXTURE/known-hosts" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -o BatchMode=yes -p 2222 keep@127.0.0.1 'test -f /opt/keep/provision.ok || test -f /opt/keep/provision.failed' 2>"$KC110_FIXTURE/ssh-readiness.log"; do
    kill -0 "$KC110_QEMU_PID" || exit 1
    sleep 2
  done
'
ssh_options=(-i "$fixture/guest-key" -o "UserKnownHostsFile=$fixture/known-hosts" -o StrictHostKeyChecking=yes -o ConnectTimeout=5 -o BatchMode=yes -p 2222)
actual_qemu_pid=$(cat "$fixture/qemu.pid")
ps -o pid,uid,gid,supgid,args -p "$actual_qemu_pid"
test "$(stat -c %u "/proc/$actual_qemu_pid")" = "$runner_uid"
ssh "${ssh_options[@]}" keep@127.0.0.1 cat /opt/kc110-provision.log | tee "$fixture/guest-provision.log"
ssh "${ssh_options[@]}" keep@127.0.0.1 test -f /opt/keep/provision.ok
ssh "${ssh_options[@]}" keep@127.0.0.1 env -i HOME=/home/keep PATH=/usr/bin:/bin LANG=C.UTF-8 \
  /opt/keep/node-v22.23.4-linux-x64/bin/node /opt/keep/guest-proof.mjs | tee "$fixture/proof.log"
python3 - <<'PY'
import os,json,pathlib
f=pathlib.Path(os.environ['KC110_FIXTURE'])
lines=(f/'proof.log').read_text().splitlines()
proofs=[json.loads(x.split('=',1)[1]) for x in lines if x.startswith('KC110_GUEST_PROOF_JSON=')]
assert len(proofs)==1 and proofs[0]['passed'] is True
print('KC110_FINAL_JSON='+json.dumps({'schema':'keep.kc110-proof-result/v1','passed':True,'runId':os.environ['GITHUB_RUN_ID'],
'source':os.environ['GITHUB_SHA'],'bootId':proofs[0]['bootId'],'uid':proofs[0]['uid'],'guestBooted':True,
'sameGuestEngineAndRequiredJail':True,'guestPolicyChanged':False,'modelCalls':0,'peakFixtureBytes':sum(p.stat().st_size for p in f.rglob('*') if p.is_file())},separators=(',',':')))
PY
