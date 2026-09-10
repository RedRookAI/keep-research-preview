import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir, homedir } from "node:os";
import { execFileSync, spawn } from "node:child_process";
import { Readable, Writable } from "node:stream";
import { ProcessIsolationAdapter } from "../src/infra/process_isolation.js";
import { prepareRequiredJail } from "../src/infra/required_project_jail.js";

function roots() {
  const root = mkdtempSync(join(tmpdir(), "keep-required-options-"));
  const project = join(root, "project"), input = join(root, "input");
  mkdirSync(project); mkdirSync(input);
  return { root, project, input };
}

test("pinned launcher withholds completion after actual late setup failure", async () => {
  const r = roots();
  const plan = prepareRequiredJail("/usr/bin/true", [], { mode: "required", projectDir: r.project }, undefined, {}, Date.now() + 5000);
  // Fault only the test launch's destination after normal admission. This reaches
  // bwrap's post-clone chdir failure, not a mocked status or product test hook.
  const args = plan.argumentBytes.toString("utf8").split("\0");
  const chdir = args.indexOf("--chdir"); assert.ok(chdir >= 0);
  args[chdir + 1] = join(r.project, "absent");
  const child = spawn(plan.cmd, plan.args, { cwd: "/", env: { PATH: "/usr/bin:/bin", LANG: "C" },
    detached: true, stdio: ["ignore", "pipe", "pipe", "pipe", "pipe", "pipe", ...plan.mounts] });
  const status: Buffer[] = [], stderr: Buffer[] = [];
  let ended = false, bytes = 0;
  const stop = () => { if (child.pid !== undefined) { try { process.kill(-child.pid, "SIGKILL"); } catch { /* already exited */ } } };
  const timeout = setTimeout(stop, 5000);
  try {
    const pipes: readonly (Readable | Writable | null | undefined)[] = child.stdio;
    const statusPipe = pipes[4], filterPipe = pipes[3], argsPipe = pipes[5];
    assert.ok(statusPipe instanceof Readable); assert.ok(filterPipe instanceof Writable); assert.ok(argsPipe instanceof Writable);
    child.stdout?.resume(); child.stderr?.on("data", (chunk: Buffer) => { bytes += chunk.length; if (bytes > 8192) stop(); else stderr.push(chunk); });
    statusPipe.on("data", (chunk: Buffer) => { plan.close(); bytes += chunk.length; if (bytes > 8192) stop(); else status.push(chunk); });
    statusPipe.once("end", () => { ended = true; });
    filterPipe.on("error", () => {}); argsPipe.on("error", () => {});
    const result = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
      child.once("error", reject); child.once("close", (code, signal) => resolve({ code, signal }));
    });
    filterPipe.end(plan.filterBytes); argsPipe.end(Buffer.from(args.join("\0")));
    const { code, signal } = await result, recorded = Buffer.concat(status), diagnostic = Buffer.concat(stderr).toString("utf8");
    assert.equal(code, 1); assert.equal(signal, null); assert.equal(ended, true);
    assert.match(recorded.toString("utf8"), /"child-pid"/u);
    assert.doesNotMatch(recorded.toString("utf8"), /"exit-code"/u);
    assert.match(diagnostic, /bwrap:.*chdir/u);
    assert.equal(plan.completed(recorded, ended, code, signal).namespaceSetup, "unverified");
  } finally { clearTimeout(timeout); stop(); plan.close(); }
});

test("required adapter does not confuse missing executable with a failing task", async () => {
  const r = roots();
  const result = await new ProcessIsolationAdapter().run(join(r.project, "missing-executable"), [], {
    cwd: r.project, timeoutMs: 5000, namespaceJail: { mode: "required", projectDir: r.project } });
  assert.equal(result.code, 1, JSON.stringify(result));
  assert.equal(result.processIsolation?.namespaceSetup, "unverified");
  assert.match(result.stderr, /bwrap:.*execvp/u);
});

test("a task's bwrap-like stderr and exit one do not negate actual launcher completion", async () => {
  const r = roots();
  const result = await new ProcessIsolationAdapter().run(process.execPath, ["-e", "console.error('bwrap: task-owned text');process.exitCode=1"], {
    cwd: r.project, timeoutMs: 5000, namespaceJail: { mode: "required", projectDir: r.project } });
  assert.equal(result.code, 1, JSON.stringify(result));
  assert.equal(result.processIsolation?.namespaceSetup, "launcher-confirmed");
  assert.match(result.stderr, /bwrap: task-owned text/u);
});

test("required mode keeps private HOME when the host HOME is allowlisted", () => {
  const r = roots();
  // Service-based test runners may omit HOME. Supply the real user's home only
  // to this fresh fixture process; never change the builder's environment.
  const hostHome = homedir(); assert.notEqual(hostHome, "/tmp/home");
  const moduleUrl = new URL("../src/infra/process_isolation.js", import.meta.url).href;
  const code = `import assert from 'node:assert/strict';import {ProcessIsolationAdapter} from ${JSON.stringify(moduleUrl)};
const project=${JSON.stringify(r.project)};
const result=await new ProcessIsolationAdapter().run(process.execPath,['-e','console.log(process.env.HOME)'],{
cwd:project,timeoutMs:5000,envAllowlist:['HOME'],namespaceJail:{mode:'required',projectDir:project}});
assert.equal(result.code,0,JSON.stringify(result));assert.equal(result.stdout.trim(),'/tmp/home');
assert.equal(result.processIsolation.namespaceSetup,'launcher-confirmed');console.log('PASS');`;
  assert.equal(execFileSync(process.execPath, ["--input-type=module", "-e", code], {
    encoding: "utf8", timeout: 10000, maxBuffer: 65536, env: { ...process.env, HOME: hostHome },
  }).trim(), "PASS");
});

test("positive sub-KiB file limits refuse before command entry instead of becoming zero", async () => {
  const r = roots(), marker = join(r.project, "started");
  for (const maxFileSizeBytes of [1, 1023]) {
    const result = await new ProcessIsolationAdapter().run(process.execPath, ["-e", `require('node:fs').writeFileSync(${JSON.stringify(marker)},'x')`], {
      cwd: r.project, timeoutMs: 5000, namespaceJail: { mode: "required", projectDir: r.project, maxFileSizeBytes } });
    assert.equal(result.completion, "not-started", JSON.stringify(result));
    assert.match(result.terminationError ?? "", /positive file-size limit.*1024/u);
    assert.equal(existsSync(marker), false);
  }
});

test("explicit zero file limit still permits an empty file and pipe output", async () => {
  const r = roots(), file = join(r.project, "empty");
  const result = await new ProcessIsolationAdapter().run(process.execPath, ["-e", `const fs=require('node:fs');fs.closeSync(fs.openSync(${JSON.stringify(file)},'w'));console.log('useful')`], {
    cwd: r.project, timeoutMs: 5000, namespaceJail: { mode: "required", projectDir: r.project, maxFileSizeBytes: 0 } });
  assert.equal(result.code, 0, JSON.stringify(result)); assert.equal(result.stdout.trim(), "useful");
  assert.equal(readFileSync(file).length, 0); assert.equal(result.processIsolation?.rlimitSetup, "launcher-confirmed");
});

for (const nested of [false, true]) test(`required mode ${nested ? "refuses a nested mount" : "accepts an explicitly selected mounted root"}`, () => {
  const r = roots(), moduleUrl = new URL("../src/infra/process_isolation.js", import.meta.url).href;
  // Both mounts and propagation changes occur only in the fresh private mount
  // namespace. The parent never mounts/unmounts an operational path.
  const code = `import assert from 'node:assert/strict';import fs from 'node:fs';import {execFileSync} from 'node:child_process';
import {ProcessIsolationAdapter} from ${JSON.stringify(moduleUrl)};
assert.notEqual(fs.readlinkSync('/proc/self/ns/mnt'),process.argv[1]);
const run=(args)=>execFileSync('mount',args,{timeout:3000});run(['--make-rprivate','/']);
const r=${JSON.stringify(r)},nested=${nested};let target=r.project;
if(nested){target=r.project+'/nested';fs.mkdirSync(target);}
run(['--bind',r.input,target]);
const marker=r.project+'/result';const result=await new ProcessIsolationAdapter().run(process.execPath,['-e',
'require("node:fs").writeFileSync('+JSON.stringify(marker)+',"42")'],{cwd:r.project,timeoutMs:5000,namespaceJail:{mode:'required',projectDir:r.project}});
if(nested){assert.equal(result.completion,'not-started',JSON.stringify(result));assert.match(result.terminationError,/nested/);assert.equal(fs.existsSync(marker),false);}
else{assert.equal(result.code,0,JSON.stringify(result));assert.equal(result.processIsolation.namespaceSetup,'launcher-confirmed');assert.equal(fs.readFileSync(r.input+'/result','utf8'),'42');}
console.log(JSON.stringify({nested,result: 'PASS'}));`;
  const parentMount = execFileSync("readlink", ["/proc/self/ns/mnt"], { encoding: "utf8" }).trim();
  const result = execFileSync("unshare", ["-Urm", process.execPath, "--input-type=module", "-e", code, parentMount], {
    encoding: "utf8", timeout: 15000, maxBuffer: 65536 });
  assert.equal(JSON.parse(result).result, "PASS");
});
