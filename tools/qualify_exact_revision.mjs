#!/usr/bin/env node
// T020: one prepared, externally bounded complete source checkpoint; no host preparation.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { closeSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const repository = resolve(fileURLToPath(new URL('..', import.meta.url)));
const outputRelative = 'docs/qualification/exact-revision-evidence.json';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const fileHash = path => hash(readFileSync(path));
const git = (root, args) => execFileSync('git', args, { cwd: root, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 });

export function sourceSnapshot(root) {
  const changes = git(root, ['status', '--porcelain=v1', '-z']).split('\0').filter(Boolean);
  // Only this runner's own report is output; every other dirty/untracked input refuses.
  assert.ok(changes.every(line => line.slice(3) === outputRelative), 'exact qualification requires clean source');
  const head = git(root, ['rev-parse', 'HEAD']).trim();
  const entries = {};
  for (const name of git(root, ['ls-files', '-z']).split('\0').filter(Boolean).sort()) {
    if (name === outputRelative) continue;
    const path = join(root, name), status = lstatSync(path);
    assert.ok(status.isFile() && !status.isSymbolicLink(), `source entry must be a regular file: ${name}`);
    entries[name] = { sha256: fileHash(path), mode: status.mode & 0o7777 };
  }
  return { head, entries, digest: hash(JSON.stringify(entries)) };
}
export function assertSameSource(root, expected) {
  assert.deepEqual(sourceSnapshot(root), expected, 'source changed during exact qualification');
}
const fixturePaths = [
  'native/target/x86_64-unknown-linux-musl/debug/keep-native-protocol-oracle',
  'native/target/x86_64-unknown-linux-musl/debug/keep-native-p2-d2-overlay-oracle',
  'native/target/x86_64-unknown-linux-musl/debug/keep-native-patch-capture',
  'native/target/x86_64-unknown-linux-musl/release/keep-native-production-resolver-probe',
  'dist/native/linux-x64/keep-native-patch-capture',
  'dist/native/linux-x64/capture-manifest.json',
];
export function nativeFixtureRecord(root, sourceDigest) {
  const files = {};
  for (const name of fixturePaths) {
    const path = join(root, name), status = lstatSync(path);
    assert.ok(status.isFile() && !status.isSymbolicLink() && (name.endsWith('.json') ? (status.mode & 0o7777) === 0o644 : (status.mode & 0o111) !== 0), `native fixture refused: ${name}`);
    files[name] = { sha256: fileHash(path), mode: status.mode & 0o7777 };
  }
  return { sourceDigest, files };
}
export function assertNativeFixtures(root, record, sourceDigest) {
  assert.deepEqual(nativeFixtureRecord(root, sourceDigest), record, 'native fixtures changed or belong to different source');
}
export function assertFullProfile(log, expectedFiles) {
  assert.match(log, /\[test:full\] profile=full phase=all workers=1;/u);
  const result = {};
  for (const label of ['ordinary', 'release/security', 'native']) {
    const marker = `[test:full] ${label}: ${expectedFiles[label]} files, concurrency 1`;
    const start = log.indexOf(marker); assert.ok(start >= 0, `required phase absent: ${label}`);
    const end = log.indexOf('[test:full]', start + marker.length);
    const phase = log.slice(start, end < 0 ? undefined : end);
    const numbers = {};
    for (const key of ['tests', 'pass', 'fail', 'cancelled', 'skipped']) {
      const matches = [...phase.matchAll(new RegExp(`^ℹ ${key} ([0-9]+)$`, 'gmu'))];
      assert.equal(matches.length, 1, `missing or ambiguous ${label} ${key} evidence`);
      numbers[key] = Number(matches[0][1]);
    }
    assert.ok(numbers.tests > 0 && numbers.pass === numbers.tests && numbers.fail === 0 && numbers.cancelled === 0 && numbers.skipped === 0, `required phase incomplete: ${label}`);
    result[label] = { files: expectedFiles[label], ...numbers };
  }
  return result;
}
export function authenticateToolchain(root, toolchainRoot) {
  const inventory = JSON.parse(readFileSync(join(root, 'native/toolchain-inventory.json')));
  for (const entry of inventory.entries) {
    const path = join(toolchainRoot, entry.path), status = lstatSync(path);
    assert.ok(status.isFile() && !status.isSymbolicLink(), `compiler entry refused: ${entry.path}`);
    assert.equal(status.size, entry.size); assert.equal(fileHash(path), entry.sha256, `compiler identity differs: ${entry.path}`);
  }
  return { toolchain: inventory.toolchain, manifestSha256: fileHash(join(root, 'native/toolchain-inventory.json')), files: inventory.entries.length };
}

export function preparedEnvironment() {
  assert.equal(process.version, 'v22.23.2'); assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64');
  const uidMap = readFileSync('/proc/self/uid_map', 'utf8').trim().split(/\s+/u).map(Number);
  assert.ok(uidMap.length === 6 && uidMap[0] === 0 && uidMap[1] > 0 && uidMap[2] === 1 &&
    uidMap[3] === 65534 && uidMap[4] > 0 && uidMap[4] !== uidMap[1] && uidMap[5] === 1 && process.getuid() === 0,
    'requires a prepared isolated mapped fixture; refusing direct shared-host execution');
  const gidMap = readFileSync('/proc/self/gid_map', 'utf8').trim().split(/\s+/u).map(Number);
  assert.deepEqual(gidMap, uidMap, 'requires the matching isolated group map for wrong-owner tests');
  assert.equal(readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
  const cg = '/sys/fs/cgroup' + readFileSync('/proc/self/cgroup', 'utf8').trim().split('::')[1];
  const controls = Object.fromEntries(['cpu.max', 'memory.max', 'memory.swap.max', 'pids.max'].map(name => [name, readFileSync(join(cg, name), 'utf8').trim()]));
  assert.deepEqual(controls, { 'cpu.max': '200000 100000', 'memory.max': '4294967296', 'memory.swap.max': '0', 'pids.max': '512' }, 'missing actual finite process-tree envelope');
  execFileSync('python3', ['--version'], { timeout: 3000 });
  execFileSync('unshare', ['-Urnm', '/usr/bin/true'], { timeout: 5000 });
  const bubblewrap = '/opt/keep/bubblewrap/0.13.0/bwrap';
  assert.equal(fileHash(bubblewrap), 'e96e817b17de74e75f9680755a700f16c9f59917a264c499175da704651bd41f');
  const tracer = '/usr/bin/strace';
  assert.equal(fileHash(tracer), '28f957c227012de0b18d1bd7fff2d396cb693ea60ed8013be68de071e84b5001');
  return { uidMap, gidMap, cgroup: cg, controls, namespaces: 'actual nested user/mount/network probe passed', bubblewrapSha256: fileHash(bubblewrap),
    guestRequirements: 'The selected full test runner does not invoke real guest/KVM/Firecracker host probes. No VM boot or host-policy preparation is authorized by this runner.' };
}

export function qualify() {
  assert.equal(process.argv.length, 2, 'exact qualification takes no arguments');
  const start = performance.now(), deadline = start + 3_300_000;
  const report = { schema: 'keep.audit.exact-revision-evidence/v1', ticket_id: 'KEEP-AUDIT-20261004-T020', status: 'NOT_QUALIFIED',
    recorded_at: new Date().toISOString(), commands: [], authorizing: false, same_agent: true,
    source_output_exception: outputRelative, profile: 'full phase=all workers=1',
    limits: 'One local source checkpoint in a prepared synthetic fixture; no deployment, organization custody, independent replication or destructive guest-host qualification.' };
  let out;
  const persist = () => writeFileSync(join(repository, outputRelative), JSON.stringify(report, null, 2) + '\n');
  try {
    const source = sourceSnapshot(repository); report.source = source;
    report.environment = preparedEnvironment();
    const lock = JSON.parse(readFileSync(join(repository, 'native/toolchain-lock.json')));
    const toolchainRoot = process.env.KEEP_P1_TOOLCHAIN_ROOT ?? join(process.env.RUSTUP_HOME ?? '/root/.keep-build/rustup', 'toolchains', lock.toolchain);
    report.toolchain = authenticateToolchain(repository, toolchainRoot);
    out = mkdtempSync(join(tmpdir(), 'keep-exact-revision-')); report.output_directory = out;
    const env = { ...process.env, KEEP_P1_TOOLCHAIN_ROOT: toolchainRoot, npm_config_offline: 'true', npm_config_audit: 'false', npm_config_fund: 'false', npm_config_userconfig: '/dev/null' };
    delete env.NODE_TEST_CONTEXT;
    const run = (label, command, args, cwd = repository, selectedEnv = env) => {
      assertSameSource(repository, source);
      const log = join(out, label + '.log'), fd = openSync(log, 'wx', 0o600), began = performance.now(); let result;
      try { result = spawnSync(command, args, { cwd, env: selectedEnv, stdio: ['ignore', fd, fd], timeout: Math.max(1, Math.floor(deadline - performance.now())), killSignal: 'SIGKILL' }); }
      finally { closeSync(fd); }
      report.commands.push({ label, command, args, cwd, exit: result.status, error: result.error?.message, seconds: (performance.now() - began) / 1000, log, logSha256: fileHash(log) });
      assert.equal(result.error, undefined); assert.equal(result.status, 0, `required command failed: ${label}`);
      assertSameSource(repository, source);
    };
    run('locked-install', 'npm', ['ci', '--ignore-scripts', '--offline']);
    run('notices', 'npm', ['run', 'test:notices']);
    run('build', 'npm', ['run', 'build']);
    // Always prepare/verify at this source; mere presence of old oracle files is ineligible.
    run('native-fixture-preparation', process.execPath, ['tools/native_p1_gate.mjs', '--verify']);
    const cargoHome = join(out, 'cargo-home'); mkdirSync(cargoHome);
    const cargoEnv = { PATH: `${join(toolchainRoot, 'bin')}:${join(toolchainRoot, 'lib/rustlib', lock.host, 'bin')}:/usr/bin:/bin`,
      LANG: 'C', LC_ALL: 'C', CARGO_HOME: cargoHome, CARGO_NET_OFFLINE: 'true', CARGO_INCREMENTAL: '0', CARGO_BUILD_JOBS: '1',
      RUSTC: join(toolchainRoot, 'bin/rustc'), RUSTDOC: join(toolchainRoot, 'bin/rustdoc'), RUSTFMT: join(toolchainRoot, 'bin/rustfmt'),
      RUSTUP_HOME: process.env.RUSTUP_HOME, RUSTUP_TOOLCHAIN: lock.toolchain, SOURCE_DATE_EPOCH: '0', RUSTFLAGS: `--remap-path-prefix=${repository}=/keep/source` };
    run('native-capture-fixture-preparation', join(toolchainRoot, 'bin/cargo'),
      ['build', '--locked', '--offline', '--frozen', '--target', lock.target, '--bin', 'keep-native-patch-capture'], join(repository, 'native'), cargoEnv);
    report.native_fixtures = nativeFixtureRecord(repository, source.digest);
    const names = readdirSync(join(repository, 'dist/test')).filter(name => name.endsWith('.test.js'));
    const expected = { ordinary: names.filter(n => !n.startsWith('native_') && n !== 'capability_graph_v2.test.js').length,
      'release/security': 1, native: names.filter(n => n.startsWith('native_')).length };
    // The capture contract measures its actual process scope, not earlier compiler
    // peaks. Keep the complete selected profile in one smaller owned child scope;
    // the unchanged outer envelope bounds this and all peer fixture units together.
    const controlsFile = join(out, 'complete-profile-controls.json'), observer = join(out, 'complete-profile-envelope.mjs');
    const childControls = { 'cpu.max': '200000 100000', 'memory.max': '2097152000', 'memory.swap.max': '0', 'pids.max': '512' };
    writeFileSync(observer, `import assert from 'node:assert/strict'; import {readFileSync,writeFileSync} from 'node:fs';
const cgroup='/sys/fs/cgroup'+readFileSync('/proc/self/cgroup','utf8').trim().split('::')[1];
const controls=Object.fromEntries(['cpu.max','memory.max','memory.swap.max','pids.max'].map(n=>[n,readFileSync(cgroup+'/'+n,'utf8').trim()]));
assert.deepEqual(controls,${JSON.stringify(childControls)});writeFileSync(${JSON.stringify(controlsFile)},JSON.stringify({cgroup,controls})+'\\n');\n`, { mode: 0o600 });
    const selectedKeys = ['PATH','HOME','TMPDIR','LANG','LC_ALL','RUSTUP_HOME','KEEP_P1_ROOT','KEEP_P1_TOOLCHAIN_ROOT','container','GIT_CONFIG_NOSYSTEM','GIT_CONFIG_GLOBAL'];
    const sets = Object.entries(env).filter(([key])=>selectedKeys.includes(key)||key.startsWith('npm_config_')).map(([key,value])=>`--setenv=${key}=${key==='TMPDIR'?'/tmp':value}`);
    const runProfileScope = (label, args) => {
      const unit = `keep-exact-${label}-${process.pid}`;
      run(label, '/usr/bin/systemd-run', ['--quiet','--wait','--pipe','--collect',`--unit=${unit}`,
      '--property=CPUQuota=200%','--property=MemoryMax=2000M','--property=MemorySwapMax=0','--property=TasksMax=512',
      `--property=RuntimeMaxSec=${Math.max(1,Math.floor((deadline-performance.now())/1000))}`,'--property=TimeoutStopSec=5','--property=KillMode=control-group',
      `--property=WorkingDirectory=${repository}`, ...sets, process.execPath, '--import', observer, ...args]);
      const observed = JSON.parse(readFileSync(controlsFile)); assert.deepEqual(observed.controls,childControls);
      return { unit, ...observed, observer, observerSha256:fileHash(observer),
        boundary:'Owned prepared manager only; all commands/peer units remain inside the same outer 2CPU/4GiB/512PID finite allowance.' };
    };
    report.native_prerequisite_envelope = runProfileScope('native-prerequisite-focus', ['--import','./dist/test/_netguard.js',
      '--test','--test-concurrency=1','--test-reporter=spec','--test-name-pattern=framed capture|capture SDK admits the composed',
      'dist/test/native_p2_archive_capture.test.js']);
    report.complete_profile_envelope = runProfileScope('complete-profile',
      ['tools/run_full_tests.mjs','--phase=all','--workers=1','--timeout-ms=3000000','--build-native-fixtures']);
    assertNativeFixtures(repository, report.native_fixtures, source.digest);
    report.phases = assertFullProfile(readFileSync(join(out, 'complete-profile.log'), 'utf8'), expected);
    assertSameSource(repository, source);
    report.status = 'QUALIFIED_EXACT_SOURCE'; report.elapsed_seconds = (performance.now() - start) / 1000;
    persist(); console.log(JSON.stringify({ status: report.status, source_head: source.head, phases: report.phases, output_directory: out }));
  } catch (error) {
    report.refusal = error.message; report.elapsed_seconds = (performance.now() - start) / 1000;
    persist(); throw error;
  }
  return report;
}
if (resolve(process.argv[1] ?? '') === fileURLToPath(import.meta.url)) qualify();
