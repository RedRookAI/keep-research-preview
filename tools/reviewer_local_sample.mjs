/** Explicit appliance-only loopback mode. Hosted HTTPS launcher stays separate.
 * node tools/reviewer_local_sample.mjs PRIVATE_ROOT PORT
 * Resumes the same controlled fixture; never resets/replays another sample. */
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, lstatSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sampleNodeToolchain } from './reviewer_node_toolchain.mjs';

const node = sampleNodeToolchain();

const childMode = process.argv[2] === '--private-child';
const args = process.argv.slice(childMode ? 3 : 2);
const [rootArg, portArg] = args, port = Number(portArg);
if (args.length !== 2 || !rootArg || !Number.isSafeInteger(port) || port < 1024 || port > 65535)
  throw new Error('Expected owned private sample root and fixed loopback port1024..65535');
const root = resolve(rootArg);
if (!childMode) {
  process.umask(0o077);
  if (!existsSync(root)) mkdirSync(root, { mode: 0o700 });
  const s = lstatSync(root);
  if (!s.isDirectory() || s.isSymbolicLink() || s.uid !== process.getuid() || (s.mode & 0o077)) throw new Error('Sample root must be private and owned');
  for (const name of ['home', 'tmp']) if (!existsSync(join(root, name))) mkdirSync(join(root, name), { mode: 0o700 });
  const child = spawn(node.executable, [fileURLToPath(import.meta.url), '--private-child', root, String(port)], {
    cwd: root, stdio: 'inherit', env: { PATH: node.bin + ':/usr/bin:/bin', HOME: join(root, 'home'), TMPDIR: join(root, 'tmp'),
      GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0' },
  });
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));
  child.on('error', error => { process.stderr.write(String(error) + '\nState retained: ' + root + '\n'); process.exitCode = 1; });
  child.on('exit', (code, signal) => { process.exitCode = code ?? (signal ? 1 : 0); });
} else {
  process.umask(0o077);
  const { randomBytes } = await import('node:crypto');
  const { createBrowserProjectFixture } = await import('../dist/src/demo/browser_project_fixture.js');
  const { startGatewayServer } = await import('../dist/src/gateway/http_gateway.js');
  const resume = existsSync(join(root, 'fixture.json'));
  const tokenFile = join(root, 'invitation-token');
  if (resume && !existsSync(tokenFile)) throw new Error('Existing fixture lacks credential; inspect retained state');
  const fixture = createBrowserProjectFixture(root, { localAppliance: true, resume, requiredJail: {
    executable: '/opt/keep/bubblewrap/0.13.0/bwrap', nodeToolchain: node.root } });
  const token = resume ? readFileSync(tokenFile, 'utf8').trim() : randomBytes(32).toString('hex');
  if (!/^[0-9a-f]{64}$/u.test(token)) throw new Error('Invalid existing sample credential');
  if (!resume) writeFileSync(tokenFile, token + '\n', { flag: 'wx', mode: 0o600 });
  const server = await startGatewayServer(fixture.app, { host: '127.0.0.1', port, token, reviewerSample: true });
  process.stdout.write(JSON.stringify({ event: 'sample-ready', privateOrigin: server.origin, root, tokenFile,
    source: fixture.source, workspaces: fixture.workspaces, baseRevision: fixture.baseRevision, resumed: resume,
    scripted: true, paidCalls: 0, execution: 'required namespace boundary', generations: fixture.generations() }) + '\n');
  let closing = false;
  const stop = async () => {
    if (closing) return; closing = true;
    fixture.app.projectRuntime.pauseDispatch(); await server.close();
    process.stdout.write(JSON.stringify({ event: 'sample-stopped', root, stateRetained: true, generations: fixture.generations(),
      unresolved: fixture.app.projectRuntime.retainedJobs().filter(job => ['queued', 'running', 'reconciliation-required'].includes(job.state)).map(job => ({ id: job.id, state: job.state })) }) + '\n');
  };
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
}
