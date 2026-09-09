// Bounded installed SG32 accounting regression, NOT whole-ticket qualification.
// Usage: node acceptance/installed_sg32_resources.mjs INSTALLED_ROOT ARCHIVE SHA256
// The outbox is an independent local oracle; no real mail/payment/model is used.
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, openSync, writeSync, fsyncSync, closeSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { join, isAbsolute } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL, fileURLToPath } from 'node:url';

const here = fileURLToPath(import.meta.url);
const rows = path => existsSync(path) ? readFileSync(path, 'utf8').trim().split('\n').filter(Boolean).map(s => JSON.parse(s)) : [];
if (process.argv[2] === '--entry-child') {
  await singleEntryChild();
} else if (process.argv[2] === '--child') {
  const [installed, dir, track, mode, phase, capText] = process.argv.slice(3);
  assert.equal(process.argv.length, 9);
  const cap = Number(capText);
  assert.ok(isAbsolute(installed) && dir.startsWith(join(tmpdir(), 'keep-installed-fleet-uncertainty-')));
  assert.ok(['owner', 'injected-tenant'].includes(track));
  assert.ok(['acknowledged', 'commit-then-throw', 'throw-before-effect', 'returned-failure', 'forged-hold', 'response-audit-failure', 'hub-refusal'].includes(mode));
  assert.ok(['first', 'restart'].includes(phase) && [1, 2].includes(cap));
  const { composeKeep, handleGatewayRequest } = await import(pathToFileURL(join(installed, 'dist/src/index.js')));
  let calls = 0, modelCalls = 0;
  const provider = { name: 'forbidden-model', isLocal: true, embed: async () => { modelCalls++; throw Error('model forbidden'); }, generate: async () => { modelCalls++; throw Error('model forbidden'); } };
  const app = composeKeep({ dataDir: join(dir, 'keep-state'), developmentProvider: provider, fleetLifecycle: { cap, maxPerBasis: 8 } });
  const tenant = track === 'injected-tenant' ? 'alpha' : undefined;
  const security = { token: 'owned-fixture', ...(tenant ? { principalFor: () => ({ id: 'alice', kind: 'human', role: 'maintainer', tenant }) } : {}) };
  const sink = join(dir, 'outbox.jsonl');
  app.infra.capabilities.register({
    descriptor: { id: 'owned-outbox', kind: 'connector', name: 'local outbox', credentialId: 'fixture-only', trust: phase === 'first' && mode === 'hub-refusal' ? 'untrusted' : 'verified', ...(tenant ? { tenant } : {}), fleet: { admissionUnits: 1, resourceDomain: 'outbox', targetArgument: 'target' } },
    invoke: async inv => {
      calls++;
      // Fault knowledge belongs to this test adapter, never an input to Keep.
      if (phase === 'first' && mode === 'throw-before-effect') throw Error('generic adapter failure');
      const fd = openSync(sink, 'a', 0o600);
      try { writeSync(fd, JSON.stringify(inv.args) + '\n'); fsyncSync(fd); } finally { closeSync(fd); }
      if (phase === 'first' && mode === 'commit-then-throw') throw Error('generic adapter failure');
      if (phase === 'first' && mode === 'returned-failure') return { ok: false, error: 'generic adapter failure' };
      if (phase === 'first' && mode === 'forged-hold') return { ok: false, held: true, error: 'adapter claims non-dispatch' };
      return { ok: true, output: { accepted: inv.args.message } };
    },
  });
  if (phase === 'first' && mode === 'response-audit-failure') {
    const stage = app.spine.stage.bind(app.spine);
    app.spine.stage = e => { if (e.payload.phase === 'response') throw Error('response record failed'); return stage(e); };
  }
  const invoke = async (id, target) => {
    const response = await handleGatewayRequest(app, { method: 'POST', path: '/fleet/invoke', query: {}, headers: { authorization: 'Bearer owned-fixture' }, body: JSON.stringify({ operationId: id, capabilityId: 'owned-outbox', operation: 'email.send', args: { target, message: id }, confirmed: true, declassify: true }) }, security);
    return { status: response.status, body: JSON.parse(response.body) };
  };
  const state = () => ({ committed: app.fleetLifecycle.committedTotal(), active: app.fleetLifecycle.active(), effects: rows(sink).length });
  const before = state();
  let duplicate;
  if (phase === 'restart') {
    duplicate = await invoke('first', 'order-a');
    assert.equal(duplicate.body.result.proceed, false);
    assert.ok(duplicate.body.result.reasons.includes('duplicate-operation-id'));
    assert.equal(calls, 0);
  }
  const response = await invoke(phase === 'first' ? 'first' : 'second', phase === 'first' || cap === 1 ? 'order-a' : 'order-b');
  const after = state();
  const replay = app.spine.verifiedReplay();
  assert.equal(replay.verification.ok, true);
  assert.equal(modelCalls, 0);
  process.stdout.write(JSON.stringify({ phase, before, after, response, duplicate, calls, modelCalls,
    // Hash validity is structural only; missing response evidence is not effect absence.
    evidence: replay.events.filter(e => e.actor === 'fleet-lifecycle' || e.payload.event === 'capability.traffic') }) + '\n');
} else {
  const [installed, archive, archiveSha] = process.argv.slice(2);
  assert.equal(process.argv.length, 5);
  assert.ok(isAbsolute(installed) && isAbsolute(archive));
  assert.equal(createHash('sha256').update(readFileSync(archive)).digest('hex'), archiveSha);
  const root = mkdtempSync(join(tmpdir(), 'keep-installed-fleet-uncertainty-')), results = [];
  for (const track of ['owner', 'injected-tenant']) for (const [mode, cap] of [
    ['acknowledged', 1], ['commit-then-throw', 1], ['throw-before-effect', 1], ['returned-failure', 1], ['forged-hold', 1], ['response-audit-failure', 1], ['hub-refusal', 1], ['commit-then-throw', 2],
  ]) {
    const dir = join(root, `${track}-${mode}-cap${cap}`); mkdirSync(dir);
    const phases = [];
    for (const phase of ['first', 'restart']) {
      const child = spawnSync(process.execPath, [here, '--child', installed, dir, track, mode, phase, String(cap)], {
        encoding: 'utf8', timeout: 15000, maxBuffer: 2097152,
        env: { PATH: process.env.PATH ?? '/usr/bin:/bin', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' },
      });
      writeFileSync(join(dir, phase + '.log'), (child.stdout ?? '') + '\n' + (child.stderr ?? ''), { flag: 'wx', mode: 0o600 });
      assert.equal(child.status, 0, child.stderr);
      phases.push(JSON.parse(child.stdout.trim()));
    }
    const [first, restart] = phases;
    const uncertain = !['acknowledged', 'hub-refusal'].includes(mode);
    assert.equal(first.response.status, uncertain ? 409 : 200);
    assert.equal(first.response.body.settlement, uncertain ? 'uncertain' : mode === 'acknowledged' ? 'committed' : 'released');
    assert.equal(first.after.active.length, uncertain ? 1 : 0);
    assert.deepEqual(restart.before, first.after);
    const progresses = cap === 2 || mode === 'hub-refusal';
    assert.equal(restart.calls, progresses ? 1 : 0);
    assert.equal(restart.after.active.length, uncertain ? 1 : 0);
    assert.equal(restart.after.committed, mode === 'acknowledged' || progresses ? 1 : 0);
    // External oracle reads durable sink bytes, not Keep's outcome declaration.
    const effects = rows(join(dir, 'outbox.jsonl'));
    const expectedEffects = (mode === 'throw-before-effect' || mode === 'hub-refusal' ? 0 : 1) + (progresses ? 1 : 0);
    assert.equal(effects.length, expectedEffects);
    assert.ok(effects.length <= cap);
    assert.ok(effects.length <= restart.after.committed + restart.after.active.length);
    results.push({ track, mode, cap, phases, sink: effects, usefulWorkWithHeadroom: cap === 2 ? progresses : null });
  }
  const singleEntry = runSingleEntry(installed, root);
  const report = { status: 'INSTALLED_UNCERTAIN_CAPACITY_REGRESSION_PASS', installed, archive, archiveSha, root, results, singleEntry, modelCalls: 0, newDependencies: 0,
    limits: 'Installed public API, injected tenant principal, durable local outbox and fresh-process restart. No production IdP, killed in-flight process, real payment/mail, concurrency, changed memory/authority, authoritative reconciliation, frontier quality or research novelty claimed. Adapter acknowledgment remains weaker than independent effect confirmation. Unknown reservations have no automatic expiry/release.' };
  writeFileSync(join(root, 'report.json'), JSON.stringify(report, null, 2), { flag: 'wx', mode: 0o600 });
  process.stdout.write(JSON.stringify({ status: report.status, cases: results.length, singleEntryCases: singleEntry.length, root, archiveSha }) + '\n');
}

// A sink appends on EVERY adapter entry: no sink-side deduplication can hide a broken claim.
async function singleEntryChild() {
  const [installed, dir, track, mode, phase] = process.argv.slice(3);
  assert.equal(process.argv.length, 8);
  assert.ok(isAbsolute(installed) && dir.startsWith(join(tmpdir(), 'keep-installed-fleet-uncertainty-')));
  assert.ok(['owner', 'injected-tenant'].includes(track));
  assert.ok(['uncertain', 'concurrent', 'ack', 'claim-before-entry'].includes(mode));
  assert.ok(['first', 'restart'].includes(phase));
  const { composeKeep, handleGatewayRequest } = await import(pathToFileURL(join(installed, 'dist/src/index.js')));
  const tenant = track === 'owner' ? undefined : 'alpha', sink = join(dir, 'sink.jsonl');
  let calls = 0, modelCalls = 0;
  const provider = { name: 'forbidden-model', isLocal: true, generate: async () => { modelCalls++; throw Error('model forbidden'); }, embed: async () => { modelCalls++; throw Error('model forbidden'); } };
  const app = composeKeep({ dataDir: join(dir, 'keep'), developmentProvider: provider, fleetLifecycle: { cap: 1, maxPerBasis: 8 } });
  app.infra.capabilities.register({ descriptor: { id: 'draft', kind: 'connector', name: 'owned draft sink', credentialId: 'fixture', trust: 'verified',
    ...(tenant ? { tenant } : {}), fleet: { admissionUnits: 1, resourceDomain: 'draft', targetArgument: 'target' } },
    invoke: async (inv, context) => {
      calls++;
      assert.equal(context?.fleetOperation?.operationId, 'one');
      assert.equal(context?.fleetOperation?.tenant, tenant ?? 'keep.n1.default');
      const fd = openSync(sink, 'a', 0o600);
      try { writeSync(fd, JSON.stringify({ target: inv.args.target, operation: context.fleetOperation }) + '\n'); fsyncSync(fd); } finally { closeSync(fd); }
      if (mode !== 'ack') throw Error('lost acknowledgment');
      return { ok: true };
    } });
  const security = { token: 'fixture', ...(tenant ? { principalFor: () => ({ id: 'alice', kind: 'human', role: 'maintainer', tenant }) } : {}) };
  const gateway = async (path, body, method = 'POST') => {
    const response = await handleGatewayRequest(app, { method, path, query: method === 'GET' ? body : {}, headers: { authorization: 'Bearer fixture' }, body: method === 'GET' ? '' : JSON.stringify(body) }, security);
    return { status: response.status, body: JSON.parse(response.body) };
  };
  const invocation = { capabilityId: 'draft', operation: 'fs.write-draft', args: { target: 'order-a' }, auditArgs: 'digest' };
  const invoke = (handle, value = invocation) => app.infra.capabilities.invoke(value, { requireVerified: true, ...(tenant ? { tenant } : {}), fleetPermit: handle });
  const state = () => ({ effects: rows(sink).length, committed: app.fleetLifecycle.committedTotal(), active: app.fleetLifecycle.active().length });
  const before = state(); let outcome;
  if (phase === 'first') {
    const admitted = await gateway('/fleet/admit', { ...invocation, operationId: 'one', capability: invocation.operation });
    assert.equal(admitted.status, 200); assert.equal(admitted.body.result.proceed, true);
    const handle = admitted.body.result.handle;
    writeFileSync(join(dir, 'handle.json'), JSON.stringify(handle), { flag: 'wx', mode: 0o600 });
    assert.equal((await invoke(handle, { ...invocation, args: { target: 'wrong' } })).ok, false);
    assert.equal(calls, 0);
    if (mode === 'claim-before-entry') {
      assert.equal(await app.fleetLifecycle.claimDispatch(handle, handle.effectDigest), true);
      outcome = 'process ends with sealed claim and no adapter entry';
    } else {
      outcome = mode === 'concurrent' ? await Promise.all([invoke(handle), invoke(handle)]) : [await invoke(handle)];
      if (mode === 'ack') assert.equal(await app.fleetLifecycle.commit(handle), true);
    }
  } else {
    const handle = JSON.parse(readFileSync(join(dir, 'handle.json'), 'utf8'));
    outcome = await invoke(handle);
    assert.equal(outcome.ok, false); assert.equal(outcome.held, false); assert.equal(calls, 0);
    assert.equal(await app.fleetLifecycle.release(handle), false);
    const excess = await gateway('/fleet/admit', { ...invocation, operationId: 'two', capability: invocation.operation });
    assert.equal(excess.body.result.proceed, false);
  }
  const sealed = app.spine.verifiedReplay().events.length;
  const observation = await gateway('/fleet/operation', { operationId: 'one' }, 'GET');
  assert.equal(observation.status, 200);
  assert.equal(observation.body.operation.effect, 'unverified');
  assert.equal(observation.body.operation.dispatch, 'claimed');
  assert.equal(app.spine.verifiedReplay().events.length, sealed, 'inspection does not seal');
  assert.equal(modelCalls, 0);
  const replay = app.spine.verifiedReplay(); assert.equal(replay.verification.ok, true);
  process.stdout.write(JSON.stringify({ before, after: state(), calls, modelCalls, outcome, observation,
    evidence: replay.events.filter(event => event.actor === 'fleet-lifecycle' || event.payload.event === 'capability.traffic') }) + '\n');
}

function runSingleEntry(installed, root) {
  const results = [];
  for (const track of ['owner', 'injected-tenant']) for (const mode of ['uncertain', 'concurrent', 'ack', 'claim-before-entry']) {
    const dir = join(root, `entry-${track}-${mode}`); mkdirSync(dir);
    const phases = [];
    for (const phase of ['first', 'restart']) {
      const child = spawnSync(process.execPath, [here, '--entry-child', installed, dir, track, mode, phase], {
        encoding: 'utf8', timeout: 15000, maxBuffer: 2097152,
        env: { PATH: process.env.PATH ?? '/usr/bin:/bin', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' },
      });
      writeFileSync(join(dir, phase + '.log'), (child.stdout ?? '') + '\n' + (child.stderr ?? ''), { flag: 'wx', mode: 0o600 });
      assert.equal(child.status, 0, child.stderr); phases.push(JSON.parse(child.stdout.trim()));
    }
    const sink = rows(join(dir, 'sink.jsonl')), [first, restart] = phases;
    assert.deepEqual(restart.before, first.after);
    assert.equal(sink.length, mode === 'claim-before-entry' ? 0 : 1);
    assert.equal(restart.after.committed, mode === 'ack' ? 1 : 0);
    assert.equal(restart.after.active, mode === 'ack' ? 0 : 1);
    assert.equal(first.calls, sink.length); assert.equal(restart.calls, 0);
    results.push({ track, mode, phases, sink, limits: 'Trusted host retry; local durable sink, process restart and same-process concurrency. No sink deduplication, external-provider finality or crash-kill claim.' });
  }
  return results;
}
