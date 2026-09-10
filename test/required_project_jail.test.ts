import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, linkSync, symlinkSync, lstatSync, readlinkSync } from "node:fs";
import { createServer } from "node:net";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { SandboxedCommandRunner, type SandboxedCommandConfig } from "../src/solve/sandboxed_runner.js";
import { ProcessIsolationAdapter } from "../src/infra/process_isolation.js";
import { prepareRequiredJail } from "../src/infra/required_project_jail.js";

// Actual local Linux command journeys, not authenticated organization admission.
// These labels alone do not qualify authenticated organization admission.
function roots() {
  const root = mkdtempSync(join(tmpdir(), "keep-required-command-"));
  const project = join(root, "project"), scratch = join(root, "scratch"), sibling = join(root, "sibling"), input = join(root, "input");
  for (const path of [project, scratch, sibling, input]) mkdirSync(path);
  return { root, project, scratch, sibling, input };
}
function runner(project: string, code: string, extra: Partial<SandboxedCommandConfig> = {}) {
  return new SandboxedCommandRunner({ command: process.execPath, args: ["-e", code],
    projectDir: project, timeoutMs: 10000, namespaceJail: "required", ...extra });
}

for (const label of ["personal", "alpha-local"]) test(`required project boundary preserves useful work: ${label}`, async () => {
  const r = roots();
  writeFileSync(join(r.sibling, "unchanged"), "outside");
  writeFileSync(join(r.input, "value"), "42");
  symlinkSync(join(r.sibling, "unchanged"), join(r.project, "outside-link"));
  const code = `const fs=require('node:fs'),a=require('node:assert/strict');
    fs.writeFileSync(${JSON.stringify(join(r.project, "useful"))},'42');
    fs.writeFileSync(${JSON.stringify(join(r.scratch, "useful"))},'42');
    a.equal(fs.readFileSync(${JSON.stringify(join(r.input, "value"))},'utf8'),'42');
    a.throws(()=>fs.writeFileSync(${JSON.stringify(join(r.sibling, "unchanged"))},'wrong'));
    a.throws(()=>fs.writeFileSync(${JSON.stringify(join(r.project, "outside-link"))},'wrong'));
    a.throws(()=>fs.writeFileSync(${JSON.stringify(join(r.input, "value"))},'wrong'));
    console.log('ok 1 - useful bounded work');`;
  const result = await runner(r.project, code, { allowWritePaths: [r.scratch], readOnlyPaths: [r.input] }).run(".");
  assert.equal(result.runnerError, undefined, JSON.stringify(result));
  assert.ok(result.results.length > 0 && result.results.every(row => row.passed));
  assert.equal(result.processIsolation?.namespacePolicy, "required");
  assert.equal(result.processIsolation?.namespaceSetup, "launcher-confirmed");
  assert.equal(readFileSync(join(r.project, "useful"), "utf8"), "42");
  assert.equal(readFileSync(join(r.scratch, "useful"), "utf8"), "42");
  assert.equal(readFileSync(join(r.sibling, "unchanged"), "utf8"), "outside");
  assert.equal(readFileSync(join(r.input, "value"), "utf8"), "42");
});

test("required project boundary refuses shared writable inode without detaching or changing it", async () => {
  const r = roots(), outside = join(r.sibling, "value"), alias = join(r.project, "alias"), marker = join(r.project, "started");
  writeFileSync(outside, "original"); linkSync(outside, alias);
  const before = lstatSync(outside);
  const result = await runner(r.project, `require('node:fs').writeFileSync(${JSON.stringify(marker)},'started')`).run(".");
  assert.equal(result.processCompletion, "not-started");
  assert.match(result.runnerError ?? "", /hard.?link|shared.*inode|single.link/u);
  assert.equal(existsSync(marker), false);
  assert.equal(readFileSync(outside, "utf8"), "original");
  assert.equal(readFileSync(alias, "utf8"), "original");
  assert.equal(lstatSync(outside).ino, before.ino); assert.equal(lstatSync(alias).ino, before.ino);
  assert.equal(lstatSync(outside).nlink, 2);
});

test("required boundary distinguishes a failed command from failed sandbox setup", async () => {
  const r = roots();
  const result = await runner(r.project, "console.log('not ok 1 - deliberate task failure');process.exitCode=7").run(".");
  assert.equal(result.runnerError, undefined, JSON.stringify(result));
  assert.ok(result.results.some(row => !row.passed));
  assert.equal(result.processIsolation?.namespaceSetup, "launcher-confirmed");
});

test("required boundary cancellation before dispatch leaves no command effect", async () => {
  const r = roots(), marker = join(r.project, "started");
  const controller = new AbortController(); controller.abort();
  const result = await runner(r.project, `require('node:fs').writeFileSync(${JSON.stringify(marker)},'started')`).run(".", { signal: controller.signal });
  assert.equal(result.processCompletion, "not-started");
  assert.equal(existsSync(marker), false);
  assert.match(result.runnerError ?? "", /abort|cancel/u);
});

test("required command uses literal argv and a private HOME without leaking launcher descriptors", async () => {
  const r = roots(), marker = join(r.project, "injected");
  const argument = `$(touch ${marker}); 'quoted'\nnext line`;
  const result = await new ProcessIsolationAdapter().run("/usr/bin/python3", ["-c", `
import os,sys,json
fds={}
for fd in os.listdir('/proc/self/fd'):
 try: fds[fd]=os.readlink('/proc/self/fd/'+fd)
 except FileNotFoundError: pass
print(json.dumps({'argument':sys.argv[1],'home':os.environ.get('HOME'),'fds':fds}))
`, argument], { cwd: r.project, timeoutMs: 5000, namespaceJail: { mode: "required", projectDir: r.project } });
  assert.equal(result.code, 0, JSON.stringify(result));
  assert.equal(result.processIsolation?.namespaceSetup, "launcher-confirmed");
  const output = JSON.parse(result.stdout) as { argument: string; home: string; fds: Record<string, string> };
  assert.equal(output.argument, argument); assert.equal(output.home, "/tmp/home");
  assert.deepEqual(Object.keys(output.fds).sort(), ["0", "1", "2"]);
  assert.equal(existsSync(marker), false);
});

test("required mode refuses a project containing a live host socket before task entry", async () => {
  const r = roots(), socketPath = join(r.project, "host.sock"), marker = join(r.project, "started");
  let entries = 0;
  const server = createServer(socket => { entries++; socket.end(); });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(socketPath, resolve); });
  try {
    const result = await runner(r.project, `require('node:fs').writeFileSync(${JSON.stringify(marker)},'started')`).run(".");
    assert.equal(result.processCompletion, "not-started");
    assert.match(result.runnerError ?? "", /socket, FIFO or device/);
    assert.equal(entries, 0); assert.equal(existsSync(marker), false);
  } finally { await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())); }
});

test("required filter blocks Unix socket and datagram socketpair creation, preserving private stream IPC", async () => {
  const r = roots();
  const code = `import socket,errno,json
denied=[]
for kind in ('socket','datagram','raw'):
 try:
  if kind=='socket': socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
  else: socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM if kind=='datagram' else socket.SOCK_RAW)
  raise AssertionError('unexpected allowed '+kind)
 except OSError as e:
  assert e.errno==errno.EPERM
  denied.append(kind)
a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
a.sendall(b'42'); assert b.recv(2)==b'42'
print(json.dumps(denied))`;
  const result = await new ProcessIsolationAdapter().run("/usr/bin/python3", ["-c", code], {
    cwd: r.project, timeoutMs: 5000, namespaceJail: { mode: "required", projectDir: r.project } });
  assert.equal(result.code, 0, JSON.stringify(result));
  assert.equal(result.processIsolation?.namespaceSetup, "launcher-confirmed");
  assert.deepEqual(JSON.parse(result.stdout), ["socket", "datagram", "raw"]);
});

test("required setup refuses impossible rlimits without executing the task", async () => {
  const r = roots(), marker = join(r.project, "started");
  const result = await new ProcessIsolationAdapter().run(process.execPath, ["-e", `require('node:fs').writeFileSync(${JSON.stringify(marker)},'started')`], {
    cwd: r.project, timeoutMs: 5000, namespaceJail: { mode: "required", projectDir: r.project, maxOpenFiles: Number.MAX_SAFE_INTEGER } });
  assert.notEqual(result.code, 0); assert.notEqual(result.processIsolation?.namespaceSetup, "launcher-confirmed");
  assert.equal(existsSync(marker), false);
});

test("required mode confirms requested limits, rounds file bounds down, and isolates network by default", async () => {
  const r = roots(), outerNet = readlinkSync("/proc/self/ns/net");
  const result = await new ProcessIsolationAdapter().run("/usr/bin/python3", ["-c", `import resource,os,json
print(json.dumps({'file':resource.getrlimit(resource.RLIMIT_FSIZE),'open':resource.getrlimit(resource.RLIMIT_NOFILE),'net':os.readlink('/proc/self/ns/net')}))`], {
    cwd: r.project, timeoutMs: 5000, namespaceJail: { mode: "required", projectDir: r.project, maxOpenFiles: 512, maxFileSizeBytes: 2047 } });
  assert.equal(result.code, 0, JSON.stringify(result));
  const output = JSON.parse(result.stdout) as { file: number[]; open: number[]; net: string };
  assert.deepEqual(output.file, [1024, 1024]); assert.deepEqual(output.open, [512, 512]);
  assert.notEqual(output.net, outerNet);
  assert.equal(result.processIsolation?.rlimitSetup, "launcher-confirmed");
});

test("required launcher parser does not accept an incomplete, forged or mismatched completion", () => {
  const r = roots();
  const plan = prepareRequiredJail("/usr/bin/true", [], { mode: "required", projectDir: r.project }, undefined, {}, Date.now()+5000);
  try {
    for (const [status, ended, code] of [[`{"child-pid":3}\n`, true, 0], [`{"child-pid":3}\n{"exit-code":0}\n`, false, 0],
      [`{"child-pid":3}\n{"exit-code":0}\n`, true, 1], [`{"child-pid":3}\n{"exit-code":0,"forged":true}\n`, true, 0]] as const) {
      assert.equal(plan.completed(Buffer.from(status), ended, code, null).namespaceSetup, "unverified");
    }
    assert.equal(plan.completed(Buffer.from(`{"child-pid":3}\n{"exit-code":0}\n`), true, 0, null).namespaceSetup, "launcher-confirmed");
  } finally { plan.close(); }
});

test("required command deadline kills the tested detached descendant before its delayed effect", async () => {
  const r = roots(), ready = join(r.project, "ready"), late = join(r.project, "late");
  const descendant = `require('node:fs').writeFileSync(${JSON.stringify(ready)},'ready');setTimeout(()=>require('node:fs').writeFileSync(${JSON.stringify(late)},'late'),1000);`;
  const code = `require('node:child_process').spawn(process.execPath,['-e',${JSON.stringify(descendant)}],{detached:true,stdio:'ignore'});setInterval(()=>{},1000);`;
  const result = await new ProcessIsolationAdapter().run(process.execPath, ["-e", code], {
    cwd: r.project, timeoutMs: 700, namespaceJail: { mode: "required", projectDir: r.project } });
  assert.equal(existsSync(ready), true, JSON.stringify(result)); assert.equal(result.timedOut, true);
  assert.notEqual(result.processIsolation?.namespaceSetup, "launcher-confirmed");
  await new Promise(resolve => setTimeout(resolve, 1100));
  assert.equal(existsSync(late), false);
});

test("required command keeps allowlisted shell startup input out of the outer launcher", async () => {
  const r = roots(), startup = join(r.sibling, "startup.sh"), marker = join(r.sibling, "wrong-startup");
  writeFileSync(startup, `printf wrong > ${JSON.stringify(marker)}\n`);
  const previous = { BASH_ENV: process.env["BASH_ENV"], KEEP_REQUIRED_TEST: process.env["KEEP_REQUIRED_TEST"] };
  const value = `synthetic 'value'; $(not-a-command)\nsecond line`;
  process.env["BASH_ENV"] = startup; process.env["KEEP_REQUIRED_TEST"] = value;
  try {
    const result = await runner(r.project, `const a=require('node:assert/strict');a.equal(process.env.KEEP_REQUIRED_TEST,${JSON.stringify(value)});console.log('ok 1 - environment')`, {
      envAllowlist: ["BASH_ENV", "KEEP_REQUIRED_TEST"],
    }).run(".");
    assert.equal(result.runnerError, undefined, JSON.stringify(result));
    assert.ok(result.results.every(row => row.passed)); assert.equal(existsSync(marker), false);
  } finally {
    for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
  }
});

test("required mode runs npm tests with useful Node fork IPC and no package downloads", async () => {
  const r = roots();
  writeFileSync(join(r.project, "package.json"), JSON.stringify({ private: true, scripts: { test: "node --test task.test.cjs" } }));
  writeFileSync(join(r.project, "child.cjs"), "process.send({answer:42});process.disconnect();");
  writeFileSync(join(r.project, "task.test.cjs"), `const {test}=require('node:test'),a=require('node:assert/strict'),{fork}=require('node:child_process');
test('fork IPC',async()=>{const child=fork('./child.cjs');const value=await new Promise((resolve,reject)=>{child.once('message',resolve);child.once('error',reject)});a.equal(value.answer,42);});`);
  const result = await new SandboxedCommandRunner({ command: "npm", args: ["--offline", "--ignore-scripts=false", "test"],
    projectDir: r.project, namespaceJail: "required", timeoutMs: 10000 }).run(".");
  assert.equal(result.runnerError, undefined, JSON.stringify(result));
  assert.ok(result.results.length > 0 && result.results.every(row => row.passed), JSON.stringify(result));
  assert.equal(result.processIsolation?.namespaceSetup, "launcher-confirmed");
});

test("required mode denies local network access unless the operator explicitly allows it", async () => {
  const r = roots(); let entries = 0;
  const server = createServer(socket => { entries++; socket.end('42'); });
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  try {
    const address = server.address(); assert.ok(address && typeof address !== 'string');
    for (const allowNet of [false, true]) {
      const code: string = `const net=require('node:net'),a=require('node:assert/strict');const s=net.createConnection({host:'127.0.0.1',port:${address.port}});
let data='';s.setTimeout(1000,()=>s.destroy(new Error('bounded-connect-timeout')));s.on('data',x=>data+=x);
s.on('error',()=>{a.equal(${allowNet},false);console.log('ok 1 - network refused')});
s.on('end',()=>{a.equal(${allowNet},true);a.equal(data,'42');console.log('ok 1 - permitted local service')});`;
      const result = await runner(r.project, code, { allowNet }).run('.');
      assert.equal(result.runnerError, undefined, JSON.stringify(result));
      assert.ok(result.results.every(row => row.passed), JSON.stringify(result));
      assert.equal(entries, allowNet ? 1 : 0);
    }
  } finally { await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())); }
});

test("required mode refuses a truthy non-boolean network opt-in", async () => {
  const r = roots(), marker = join(r.project, 'wrong');
  const result = await runner(r.project, `require('node:fs').writeFileSync(${JSON.stringify(marker)},'wrong')`, {
    allowNet: 'false' as unknown as boolean,
  }).run('.');
  assert.equal(result.processCompletion, 'not-started'); assert.match(result.runnerError ?? '', /allowNet must be boolean/);
  assert.equal(existsSync(marker), false);
});
