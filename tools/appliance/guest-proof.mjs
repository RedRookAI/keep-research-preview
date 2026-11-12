/** Actual installed SDK/helper/engine check, run as the imported guest owner. */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import os from 'node:os';
const runtime = '/opt/keep/runtime', toolchain = '/opt/keep/node-v22.23.4-linux-x64';
const helper = '/opt/keep/bubblewrap/0.13.0/bwrap', engine = runtime + '/engines/codex-generation.2/bin/codex';
const node = toolchain + '/bin/node';
const read = p => { try { return readFileSync(p, 'utf8').trim(); } catch { return null; } };
const receipt = { schema: 'keep.appliance.guest-proof/v1', passed: false, uid: process.getuid(), arch: process.arch,
  bootId: read('/proc/sys/kernel/random/boot_id'), kernel: os.release(), apparmorEnabled: read('/sys/module/apparmor/parameters/enabled'),
  apparmorCurrent: read('/proc/self/attr/current'), modelCalls: 0, hashes: {}, commands: [] };
try {
  assert.notEqual(process.getuid(), 0); assert.equal(process.arch, 'x64');
  const metadata = JSON.parse(readFileSync('/opt/keep/image-build.json', 'utf8'));
  receipt.source = metadata.source; receipt.version = JSON.parse(readFileSync(runtime + '/package.json', 'utf8')).version;
  assert.equal(receipt.version, metadata.version);
  for (const [name, path, wanted] of [
    ['node', node, '94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90'],
    ['helper', helper, 'e96e817b17de74e75f9680755a700f16c9f59917a264c499175da704651bd41f'],
    ['engine', engine, 'fdd9a1a3e86fc2213e4c0bd9c9b278080f38d756a5256e3217092a30e48d98c1'],
  ]) { const hash = createHash('sha256').update(readFileSync(path)).digest('hex'); receipt.hashes[name] = hash; assert.equal(hash, wanted); }
  const work = mkdtempSync('/home/keep/guest-proof-'), home = join(work, 'home'), probe = join(work, 'probe');
  mkdirSync(home, { mode: 0o700 }); mkdirSync(probe, { mode: 0o700 });
  for (const key of Object.keys(process.env)) delete process.env[key];
  Object.assign(process.env, { HOME: home, PATH: toolchain + '/bin:/usr/bin:/bin', LANG: 'C.UTF-8' });
  for (const [args, status, pattern] of [[['--version'], 0, /codex-cli 0\.163\.0-keep-generation\.2/u], [['login', 'status'], 1, /Not logged in/u]]) {
    const r = spawnSync(engine, args, { env: process.env, encoding: 'utf8', timeout: 600_000, maxBuffer: 8 * 1024 * 1024 });
    receipt.commands.push({ args, status: r.status, stdout: r.stdout, stderr: r.stderr });
    assert.equal(r.error, undefined); assert.equal(r.status, status); assert.match(r.stdout + r.stderr, pattern);
  }
  const { SandboxedCommandRunner } = await import(pathToFileURL(runtime + '/dist/src/index.js'));
  writeFileSync(join(probe, 'probe.cjs'), "const test=require('node:test'),assert=require('node:assert/strict');test('imported guest required jail',()=>assert.equal(1+1,2));\n", { flag: 'wx', mode: 0o600 });
  receipt.preflight = await new SandboxedCommandRunner({ command: node, args: ['--test', '--test-reporter=tap', 'probe.cjs'], projectDir: probe,
    namespaceJail: 'required', jailExecutable: helper, readOnlyPaths: [toolchain], allowNet: false, envAllowlist: [],
    timeoutMs: 600_000, cpuLimitSec: 600, maxOutputBytes: 8 * 1024 * 1024 }).run('.');
  assert.equal(receipt.preflight.runnerError, undefined); assert.equal(receipt.preflight.results.length, 1); assert.equal(receipt.preflight.results[0].passed, true);
  const isolation = receipt.preflight.processIsolation;
  assert.equal(isolation.namespacePolicy, 'required'); assert.equal(isolation.basis, 'launcher-status');
  assert.equal(isolation.namespaceSetup, 'launcher-confirmed'); assert.equal(isolation.rlimitSetup, 'launcher-confirmed'); assert.deepEqual(isolation.degraded, []);
  for (const name of ['mount-ns', 'pid-ns', 'ipc-ns', 'uts-ns', 'net-ns']) assert.ok(isolation.requestedNamespaces.includes(name));
  receipt.passed = true;
} catch (error) { receipt.error = String(error.stack ?? error); process.exitCode = 1; }
console.log(JSON.stringify(receipt));
