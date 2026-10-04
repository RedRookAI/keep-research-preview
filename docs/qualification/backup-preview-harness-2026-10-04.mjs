#!/usr/bin/env node
// Separately versioned same-agent external harness: this file is not in the earlier T004 archive.
// Usage: node acceptance/installed_backup_recovery_journey.mjs EXACT_ARCHIVE ABSENT_TARGET
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, readdirSync, realpathSync, writeFileSync, writeSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = fileURLToPath(import.meta.url), harnessVersion = 2;
const sha = value => createHash('sha256').update(value).digest('hex');
const fileSha = path => sha(readFileSync(path));
const rows = path => existsSync(path) ? readFileSync(path, 'utf8').split('\n').filter(Boolean).map(row => JSON.parse(row)) : [];
const load = (root, module) => import(pathToFileURL(join(root, 'dist/src', module)));
const env = () => ({ PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: process.env.HOME ?? tmpdir(), TMPDIR: tmpdir(),
  npm_config_cache: process.env.npm_config_cache ?? join(tmpdir(), 'keep-backup-empty-cache'), npm_config_offline: 'true',
  npm_config_audit: 'false', npm_config_fund: 'false', npm_config_ignore_scripts: 'false', npm_config_userconfig: '/dev/null',
  GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' });
function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, env: env(), encoding: 'utf8', timeout: 90_000, maxBuffer: 4 * 1024 * 1024 });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  return result;
}
function inventory(root) {
  const result = {};
  function walk(path, relative = '') {
    for (const name of readdirSync(path).sort()) {
      const key = relative ? `${relative}/${name}` : name, entry = join(path, name), status = lstatSync(entry);
      assert.equal(status.isSymbolicLink(), false, key);
      if (status.isDirectory()) { result[key] = { kind: 'directory', mode: status.mode & 0o7777 }; walk(entry, key); }
      else { assert.equal(status.isFile(), true, key); result[key] = { kind: 'file', mode: status.mode & 0o7777, bytes: status.size, sha256: fileSha(entry) }; }
    }
  }
  walk(root); return result;
}

if (process.argv[2] === '--fixture-child') {
  const [product, state, sink, track, phase] = process.argv.slice(3);
  assert.equal(process.argv.length, 8);
  assert.ok(['owner', 'injected-tenant'].includes(track) && ['first', 'restart'].includes(phase));
  const { composeKeep, handleGatewayRequest } = await load(product, 'index.js');
  let calls = 0, modelCalls = 0;
  const provider = { name: 'forbidden-backup-model', isLocal: true,
    generate: async () => { modelCalls++; throw Error('model forbidden'); },
    embed: async () => { modelCalls++; throw Error('model forbidden'); } };
  const app = composeKeep({ dataDir: state, developmentProvider: provider, fleetLifecycle: { cap: 2, maxPerBasis: 8 } });
  const tenant = track === 'injected-tenant' ? 'alpha' : undefined;
  const security = { token: 'owned-backup-fixture', ...(tenant ? { principalFor: () => ({ id: 'alice', kind: 'human', role: 'maintainer', tenant }) } : {}) };
  app.infra.capabilities.register({ descriptor: { id: 'backup-outbox', kind: 'connector', name: 'local durable recovery sink', credentialId: 'fixture',
    trust: 'verified', ...(tenant ? { tenant } : {}), fleet: { admissionUnits: 1, resourceDomain: 'outbox', targetArgument: 'target' } },
    invoke: async inv => {
      calls++;
      const fd = openSync(sink, 'a', 0o600);
      try { writeSync(fd, JSON.stringify(inv.args) + '\n'); fsyncSync(fd); } finally { closeSync(fd); }
      if (phase === 'first') throw Error('lost synthetic acknowledgment');
      return { ok: true, output: { delivered: true } };
    } });
  const invoke = async (id, target) => {
    const response = await handleGatewayRequest(app, { method: 'POST', path: '/fleet/invoke', query: {},
      headers: { authorization: 'Bearer owned-backup-fixture' }, body: JSON.stringify({ operationId: id,
        capabilityId: 'backup-outbox', operation: 'email.send', args: { target, message: id }, confirmed: true, declassify: true }) }, security);
    return { status: response.status, body: JSON.parse(response.body) };
  };
  const stateNow = () => ({ active: app.fleetLifecycle.active().length, committed: app.fleetLifecycle.committedTotal(), effects: rows(sink).length });
  const before = stateNow(); let duplicate, afterDuplicate;
  if (phase === 'restart') {
    duplicate = await invoke('uncertain-one', 'order-a');
    assert.equal(duplicate.body.result.proceed, false);
    assert.ok(duplicate.body.result.reasons.includes('duplicate-operation-id'));
    assert.equal(calls, 0); afterDuplicate = stateNow(); assert.deepEqual(afterDuplicate, before);
  }
  const response = await invoke(phase === 'first' ? 'uncertain-one' : 'new-two', phase === 'first' ? 'order-a' : 'order-b');
  const replay = app.spine.verifiedReplay(); assert.equal(replay.verification.ok, true); assert.equal(modelCalls, 0);
  assert.ok(replay.events.some(event => event.payload.event === 'fleet.dispatch-claimed' && event.payload.operationId === 'uncertain-one'));
  assert.equal(stateNow().active, 1);
  process.stdout.write(JSON.stringify({ before, after: stateNow(), afterDuplicate, duplicate, response, calls, modelCalls,
    uncertainDispatchClaimRetained: true, verifiedReplay: true }) + '\n');
} else {
  const [archiveArgument, targetArgument, receiptArgument] = process.argv.slice(2);
  assert.equal(process.argv.length, 5, 'provide exact archive, owned absent target and explicit source-qualified package receipt');
  assert.ok(isAbsolute(receiptArgument));
  assert.ok(isAbsolute(archiveArgument) && isAbsolute(targetArgument));
  assert.notEqual(process.getuid(), 0, 'run the installed journey as an unprivileged fixture user');
  const archive = resolve(archiveArgument), target = resolve(targetArgument);
  assert.ok(lstatSync(archive).isFile() && !lstatSync(archive).isSymbolicLink());
  assert.equal(existsSync(target), false, 'restore target must be absent');
  const parent = dirname(target); assert.equal(realpathSync(parent), parent); assert.equal(lstatSync(parent).uid, process.getuid());
  const releaseRecord = resolve(receiptArgument);
  const release = JSON.parse(readFileSync(releaseRecord, 'utf8'));
  assert.equal(release.status, 'BUILT_FROM_QUALIFIED_SOURCE'); assert.equal(fileSha(archive), release.archive_sha256);
  const root = mkdtempSync(join(tmpdir(), 'keep-installed-backup-')), prefix = join(root, 'prefix');
  // Resolve the existing runtime dependency inside the installed product, without adding a dependency.
  const install = run('npm', ['install', '--prefix', prefix, '--install-strategy=nested', '--bin-links=false',
    '--offline', '--omit=dev', '--no-audit', '--no-fund', archive], root);
  writeFileSync(join(root, 'install.log'), install.stdout + '\n' + install.stderr, { mode: 0o600 });
  const installed = join(prefix, 'node_modules/keep');
  assert.equal(JSON.parse(readFileSync(join(installed, 'package.json'))).version, release.package_version);
  assert.equal(JSON.parse(readFileSync(join(installed, 'node_modules/typescript/package.json'))).version, '5.9.3');
  const { composeLifecycle } = await load(installed, 'lifecycle/compose_lifecycle.js'); const lifecycle = composeLifecycle();
  const { LocalBackup, buildSnapshot } = await load(installed, 'backup/backup_port.js');
  const { Ed25519SupplyChainSigner } = await load(installed, 'backup/supply_chain_backup.js');
  mkdirSync(target, { mode: 0o700 });
  const results = [];
  for (const track of ['owner', 'injected-tenant']) {
    const fixture = join(root, track); mkdirSync(fixture, { mode: 0o700 });
    const state = join(fixture, 'state'), sink = join(fixture, 'independent-outbox.jsonl');
    const first = JSON.parse(run(process.execPath, [here, '--fixture-child', installed, state, sink, track, 'first'], fixture).stdout);
    assert.deepEqual(first.after, { active: 1, committed: 0, effects: 1 }); assert.equal(first.calls, 1);
    // The only fixture writer has exited. No operational writer is stopped.
    const productBefore = inventory(installed), stateBefore = inventory(state);
    for (const name of ['chain.jsonl', 'staging.jsonl', 'staging.cursor', 'witness.jsonl', 'projects/master.key']) assert.ok(stateBefore[name], name);
    const authority = join(fixture, 'external-recovery-authority'); mkdirSync(authority, { mode: 0o700 });
    const secret = randomBytes(32).toString('base64'), salt = lifecycle.PassphraseBackupCredentialProtector.generateBindingSalt();
    writeFileSync(join(authority, 'protector.json'), JSON.stringify({ secret, salt }), { mode: 0o600, flag: 'wx' });
    const protector = new lifecycle.PassphraseBackupCredentialProtector(`${track}-recovery`, secret, salt);
    const capture = await lifecycle.captureInstalledBackup({ installedRoot: installed, stateRoot: state, credentialProtector: protector });
    assert.equal(lifecycle.verifyInstalledBackup(capture), true); assert.equal(capture.operationalRecoveryComplete, true);
    assert.equal(capture.exclusions.length, 0, 'qualified nested product/state capture must retain every entry');
    assert.equal(capture.files.some(file => file.scope === 'state'), false, 'all state is protected');
    const serialized = JSON.stringify(capture);
    assert.equal(serialized.includes(secret), false);
    assert.equal(serialized.includes(readFileSync(join(state, 'projects/master.key')).toString('base64')), false);
    const captureFile = join(fixture, 'capture.json'); writeFileSync(captureFile, serialized, { mode: 0o600, flag: 'wx' });
    assert.deepEqual(inventory(installed), productBefore); assert.deepEqual(inventory(state), stateBefore);
    const producer = generateKeyPairSync('ed25519'), witness = generateKeyPairSync('ed25519'), backup = new LocalBackup();
    for (const [name, keys] of [['producer', producer], ['witness', witness]])
      writeFileSync(join(authority, `${name}.key`), keys.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
    const lockDigest = fileSha(join(prefix, 'package-lock.json'));
    const protectedBackup = await lifecycle.createProtectedBackup({ snapshot: buildSnapshot([], sha, 1),
      artifactInventoryDigest: capture.inventoryDigest, dependencyLockDigest: lockDigest, producer: new Ed25519SupplyChainSigner(`${track}-producer`, producer.privateKey),
      witness: new Ed25519SupplyChainSigner(`${track}-witness`, witness.privateKey), backup, now: Date.now() });
    const signing = { protectedBackup, backup, trust: { producerKeys: new Map([[`${track}-producer`, producer.publicKey]]),
      witnessKeys: new Map([[`${track}-witness`, witness.publicKey]]) }, expectedDependencyLockDigest: lockDigest, hasher: sha };
    const restored = join(target, track), rejected = [];
    const tampered = structuredClone(capture); tampered.files[0].contentBase64 = Buffer.from('tampered').toString('base64');
    for (const [name, input, opener, pattern] of [['tampered', tampered, protector, /failed verification/],
      ['missing-protector', capture, undefined, /external credential recovery authority/]]) {
      const absent = join(target, `${track}-${name}`);
      await assert.rejects(lifecycle.restoreInstalledBackup({ capture: input, targetRoot: absent, signing, ...(opener ? { credentialOpener: opener } : {}) }), pattern);
      assert.equal(existsSync(absent), false); rejected.push(name);
    }
    const occupied = join(target, `${track}-occupied`); mkdirSync(occupied); writeFileSync(join(occupied, 'preserve.txt'), 'preserve owned marker', { mode: 0o600 });
    const occupiedBefore = inventory(occupied);
    await assert.rejects(lifecycle.restoreInstalledBackup({ capture, targetRoot: occupied, signing, credentialOpener: protector }), /must be absent/);
    assert.deepEqual(inventory(occupied), occupiedBefore); rejected.push('occupied');
    const report = await lifecycle.restoreInstalledBackup({ capture, targetRoot: restored, signing, credentialOpener: protector });
    assert.equal(report.componentSetComplete, true); assert.equal(report.signing.status, 'distinct-signing-keys-verified');
    assert.match(report.signing.limitation, /real-world custody/);
    assert.deepEqual(inventory(report.productTarget), productBefore); assert.deepEqual(inventory(report.stateTarget), stateBefore);
    const restart = JSON.parse(run(process.execPath, [here, '--fixture-child', report.productTarget, report.stateTarget, sink, track, 'restart'], fixture).stdout);
    assert.deepEqual(restart.before, first.after); assert.deepEqual(restart.afterDuplicate, first.after);
    assert.deepEqual(restart.after, { active: 1, committed: 1, effects: 2 }); assert.equal(restart.calls, 1);
    const actualSink = rows(sink); assert.equal(actualSink.length, 2);
    assert.deepEqual(actualSink.map(row => row.target), ['order-a', 'order-b']);
    results.push({ track, first, restart, captureId: capture.id, captureFile, captureSha256: fileSha(captureFile),
      inventoryDigest: capture.inventoryDigest, productInventory: productBefore, capturedStateInventory: stateBefore,
      restoredProductInventoryMatches: true, restoredStateBeforeRestartMatches: true, report, rejected,
      sidecars: ['chain.jsonl', 'staging.jsonl', 'staging.cursor', 'witness.jsonl', 'projects/master.key'],
      protectedCredentialFiles: capture.protectedFiles.length, protectorSecretOutsideCapture: true,
      signingKeys: { producer: sha(producer.publicKey.export({ type: 'spki', format: 'der' })), witness: sha(witness.publicKey.export({ type: 'spki', format: 'der' })),
        custody: 'Two distinct synthetic keys held by one fixture principal on one host; no organization or outside custody.' },
      independentSink: sink, actualSink, actualSinkSha256: fileSha(sink) });
  }
  const report = { schema: 'keep.installed-backup-recovery-journey/v1', harnessVersion, status: 'PASS', archive,
    archiveSha256: fileSha(archive), archiveSourceHead: release.source_head, harnessSha256: fileSha(here),
    releaseRecordSha256: fileSha(releaseRecord), uid: process.getuid(), root, target, installed, results,
    modelCalls: 0, runtimeDependency: { name: 'typescript', version: '5.9.3', installation: 'existing dependency nested within captured installed product' },
    externalHarnessNotPackagedByEarlierArchive: true, limits: 'Quiescent synthetic fixture, actual protected capture/restore, fresh-process restart and local sink. No operational backup, real credentials, offsite survival, independently custodied keys, authenticated tenant organization or universal exactly-once external effects.' };
  writeFileSync(join(root, 'report.json'), JSON.stringify(report, null, 2), { mode: 0o600, flag: 'wx' });
  process.stdout.write(JSON.stringify({ status: report.status, tracks: results.length, root, target, archiveSha256: report.archiveSha256,
    harnessSha256: report.harnessSha256, modelCalls: 0 }) + '\n');
}
