#!/usr/bin/env bash
# Called by the fixture under its existing 600-second technical boot timeout.
set -euo pipefail
until test -s "$KC110_FIXTURE/qemu.pid"; do
  test -d "/proc/$KC110_QEMU_PID" || exit 1
  sleep 0.1
done
actual_pid=$(cat "$KC110_FIXTURE/qemu.pid")
[[ "$actual_pid" =~ ^[0-9]+$ ]]
until ssh -i "$KC110_FIXTURE/guest-key" \
    -o "UserKnownHostsFile=$KC110_FIXTURE/known-hosts" \
    -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -o BatchMode=yes \
    -p 2222 keep@127.0.0.1 \
    'test -f /opt/keep/provision.ok || test -f /opt/keep/provision.failed' \
    2>"$KC110_FIXTURE/ssh-readiness.log"; do
  # Probe the actual same-owner QEMU, rather than sudo's possible root monitor.
  kill -0 "$actual_pid" || exit 1
  sleep 2
done
