/** Foreground, single controlled reviewer instance. No DNS/proxy/service changes.
 * node tools/reviewer_sample.mjs NEW_PRIVATE_ROOT CANONICAL_HTTPS_ORIGIN [PORT]
 * Credentials are written only to NEW_PRIVATE_ROOT/invitation-token (0600).
 * Run from a compiled source/package. Refuses an existing root; never resets state. */
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const childMode = process.argv[2] === '--private-child';
const args = process.argv.slice(childMode ? 3 : 2);
const [rootArg, origin, portArg = '0'] = args;
if (!rootArg || !origin || args.length > 3) throw new Error('Expected new private root, canonical HTTPS origin and optional port');
const root = resolve(rootArg), port = Number(portArg);
const parsed = new URL(origin);
if (parsed.protocol !== 'https:' || parsed.origin !== origin || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash)
  throw new Error('Canonical HTTPS origin required');
if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('Invalid listener port');
if (!childMode) {
  process.umask(0o077);
  mkdirSync(root, { mode: 0o700 }); // Existing state is always refused, including symlinks.
  for (const name of ['home', 'tmp']) mkdirSync(join(root, name), { mode: 0o700 });
  const child = spawn(process.execPath, [fileURLToPath(import.meta.url), '--private-child', root, origin, String(port)], {
    cwd: root, stdio: 'inherit', env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: join(root, 'home'), TMPDIR: join(root, 'tmp'),
      GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0' },
  });
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));
  child.on('error', error => { process.stderr.write(`Sample child could not start: ${error.message}\nState retained: ${root}\n`); process.exitCode = 1; });
  child.on('exit', (code, signal) => { process.exitCode = code ?? (signal ? 1 : 0); });
} else {
  process.umask(0o077);
  const { randomBytes } = await import('node:crypto');
  const { createBrowserProjectFixture } = await import('../dist/src/demo/browser_project_fixture.js');
  const { startGatewayServer } = await import('../dist/src/gateway/http_gateway.js');
  const fixture = createBrowserProjectFixture(root), token = randomBytes(32).toString('hex');
  const tokenFile = join(root, 'invitation-token');
  writeFileSync(tokenFile, token + '\n', { flag: 'wx', mode: 0o600 });
  const server = await startGatewayServer(fixture.app, { host: '127.0.0.1', port, token, publicBrowserOrigin: origin, reviewerSample: true });
  process.stdout.write(JSON.stringify({ event: 'sample-ready', privateOrigin: server.origin, publicBrowserOrigin: origin,
    root, tokenFile, source: fixture.source, workspaces: fixture.workspaces, baseRevision: fixture.baseRevision,
    scripted: true, paidCalls: 0, access: 'one operator-assigned invitation instance', execution: 'existing best-effort process profile' }) + '\n');
  let closing = false;
  const stop = async () => {
    if (closing) return; closing = true;
    fixture.app.projectRuntime.pauseDispatch();
    await server.close();
    const jobs = fixture.app.projectRuntime.retainedJobs();
    process.stdout.write(JSON.stringify({ event: 'sample-stopped', root, stateRetained: true,
      unresolved: jobs.filter(job => ['queued', 'running', 'reconciliation-required'].includes(job.state)).map(job => ({ id: job.id, state: job.state })) }) + '\n');
    // Normal process exit leaves the durable running lease for explicit reconciliation.
    // Never signal a replacement run, clean the instance, or rewrite an uncertain outcome.
  };
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
}
