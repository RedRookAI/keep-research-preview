// KC110's one same-guest, credential-free capability proof; no model calls.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, statSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import os from 'node:os';

const installed = '/opt/keep/runtime/keep-0.0.21-preview.1';
const toolchain = '/opt/keep/node-v22.23.4-linux-x64';
const node = join(toolchain, 'bin/node');
const engine = join(installed, 'engines/codex-generation.2/bin/codex');
const helper = '/opt/keep/bubblewrap/0.13.0/bwrap';
const expected = {
  node: '94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90',
  engine: 'fdd9a1a3e86fc2213e4c0bd9c9b278080f38d756a5256e3217092a30e48d98c1',
  helper: 'e96e817b17de74e75f9680755a700f16c9f59917a264c499175da704651bd41f',
};
const read = path => { try { return readFileSync(path, 'utf8').trim(); } catch { return null; } };
const evidence = { schema: 'keep.kc110-same-guest/v1', stage: 'inputs', passed: false,
  bootId: read('/proc/sys/kernel/random/boot_id'), uid: process.getuid(), gid: process.getgid(),
  arch: process.arch, kernel: os.release(), osRelease: read('/etc/os-release'),
  apparmorEnabled: read('/sys/module/apparmor/parameters/enabled'),
  apparmorUsernsRestriction: read('/proc/sys/kernel/apparmor_restrict_unprivileged_userns'),
  apparmorCurrent: read('/proc/self/attr/current'), unprivilegedUsernsClone: read('/proc/sys/kernel/unprivileged_userns_clone'),
  maxUserNamespaces: read('/proc/sys/user/max_user_namespaces'), hashes: {}, commands: [], modelCalls: 0,
  policyChanged: false };
try {
  assert.ok(process.getuid() !== 0); assert.equal(process.arch, 'x64'); assert.equal(process.platform, 'linux');
  const work = mkdtempSync('/home/keep/kc110-proof-');
  const home = join(work, 'home'), temp = join(work, 'tmp'), probe = join(work, 'probe');
  for (const directory of [home, temp, probe]) mkdirSync(directory, { mode: 0o700 });
  // The process and all child commands get only this deliberately empty-account environment.
  for (const key of Object.keys(process.env)) delete process.env[key];
  Object.assign(process.env, { PATH: `${toolchain}/bin:/usr/bin:/bin`, HOME: home, TMPDIR: temp,
    LANG: 'C.UTF-8', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0' });
  for (const [name, path] of Object.entries({ node, engine, helper })) {
    const hash = createHash('sha256').update(readFileSync(path)).digest('hex');
    evidence.hashes[name] = hash; assert.equal(hash, expected[name]);
    const s = statSync(path); assert.equal(s.uid, 0); assert.equal(s.mode & 0o6022, 0);
  }
  const pkg = JSON.parse(readFileSync(join(installed, 'package.json'), 'utf8'));
  assert.equal(pkg.version, '0.0.21-preview.1'); assert.equal(pkg.exports['.'], './dist/src/index.js');
  function command(executable, args, expectedStatus) {
    const r = spawnSync(executable, args, { env: process.env, cwd: work, encoding: 'utf8',
      timeout: 600_000, maxBuffer: 8 * 1024 * 1024 });
    const observation = { executable, args, status: r.status, signal: r.signal, error: r.error?.message,
      stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
    evidence.commands.push(observation);
    assert.equal(r.error, undefined); assert.equal(r.status, expectedStatus); return observation;
  }
  evidence.stage = 'engine-version';
  const version = command(engine, ['--version'], 0);
  assert.equal(version.stdout.trim(), 'codex-cli 0.163.0-keep-generation.2');
  evidence.stage = 'engine-logged-out';
  const login = command(engine, ['login', 'status'], 1);
  assert.match(login.stdout + login.stderr, /Not logged in/iu);
  evidence.stage = 'required-jail-preflight';
  const { SandboxedCommandRunner } = await import(pathToFileURL(join(installed, pkg.exports['.'])));
  writeFileSync(join(probe, 'probe.cjs'), "const test=require('node:test'),assert=require('node:assert/strict');test('required jail can execute selected Node',()=>assert.equal(1+1,2));\n", { flag: 'wx', mode: 0o600 });
  const preflight = await new SandboxedCommandRunner({ command: node,
    args: ['--test', '--test-reporter=tap', 'probe.cjs'], projectDir: probe,
    namespaceJail: 'required', jailExecutable: helper, readOnlyPaths: [toolchain], allowNet: false,
    envAllowlist: [], timeoutMs: 600_000, cpuLimitSec: 600, maxOutputBytes: 8 * 1024 * 1024 }).run('.');
  evidence.preflight = preflight;
  assert.equal(preflight.runnerError, undefined);
  assert.equal(preflight.results.length, 1); assert.equal(preflight.results[0].passed, true);
  assert.equal(preflight.processIsolation?.namespacePolicy, 'required');
  assert.equal(preflight.processIsolation.namespaceSetup, 'launcher-confirmed');
  assert.equal(preflight.processIsolation.basis, 'launcher-status');
  assert.equal(preflight.processIsolation.rlimitSetup, 'launcher-confirmed');
  assert.deepEqual(preflight.processIsolation.degraded, []);
  for (const name of ['mount-ns', 'pid-ns', 'ipc-ns', 'uts-ns', 'net-ns'])
    assert.ok(preflight.processIsolation.requestedNamespaces.includes(name));
  evidence.stage = 'complete'; evidence.passed = true;
} catch (error) {
  evidence.error = error.stack ?? String(error); process.exitCode = 1;
} finally {
  console.log('KC110_GUEST_PROOF_JSON=' + JSON.stringify(evidence));
}
