import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, symlinkSync, readlinkSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, relative, isAbsolute, sep } from "node:path";
import { tmpdir } from "node:os";
import { prepareRequiredJail } from "../src/infra/required_project_jail.js";
import { ProcessIsolationAdapter } from "../src/infra/process_isolation.js";
import type { NamespaceJailSpec } from "../src/infra/isolation_backend.js";

function inside(root: string, value: string): boolean {
  const r = relative(root, value);
  return r === "" || (!isAbsolute(r) && r !== ".." && !r.startsWith(".." + sep));
}
function directory(root: string, name: string): string {
  const path = join(root, name); mkdirSync(path, { recursive: true }); return path;
}

// Upstream GHSA-pxhw-h44j-8pfx concerns creation below untrusted mounted
// content during setup. Check the actual finite launcher plan, not source text.
// Unknown options fail this test and require an explicit effect classification.
function inspectLayout(bytes: Buffer): { mounted: string[]; setup: { option: string; target: string }[] } {
  const tokens = bytes.toString("utf8").split("\0");
  assert.equal(tokens.pop(), "");
  const arity: Record<string, number> = {
    "--unshare-user": 0, "--unshare-pid": 0, "--unshare-ipc": 0, "--unshare-uts": 0,
    "--unshare-net": 0, "--disable-userns": 0, "--assert-userns-disabled": 0,
    "--cap-drop": 1, "--new-session": 0, "--die-with-parent": 0,
    "--ro-bind-fd": 2, "--bind-fd": 2, "--symlink": 2,
    "--tmpfs": 1, "--dir": 1, "--proc": 1, "--dev": 1,
    "--chdir": 1, "--json-status-fd": 1, "--seccomp": 1, "--clearenv": 0, "--setenv": 2,
  };
  const mounts = new Set(["--ro-bind-fd", "--bind-fd"]);
  const creates = new Set([...mounts, "--symlink", "--tmpfs", "--dir", "--proc", "--dev"]);
  const mounted: string[] = [], setup: { option: string; target: string }[] = [];
  for (let i = 0; i < tokens.length;) {
    const option = tokens[i++]!;
    assert.ok(Object.hasOwn(arity, option), `unclassified launcher option: ${option}`);
    const count = arity[option]!, args = tokens.slice(i, i + count); i += count;
    assert.equal(args.length, count);
    if (!creates.has(option)) continue;
    const target = args.at(-1)!; assert.ok(isAbsolute(target));
    assert.ok(!mounted.some(root => inside(root, target)), `${option} creates ${target} inside previously mounted caller content`);
    setup.push({ option, target });
    if (mounts.has(option)) {
      if (target === "/usr") { assert.equal(setup.length, 1); assert.equal(option, "--ro-bind-fd"); }
      else mounted.push(target);
    }
  }
  assert.equal(setup[0]?.target, "/usr");
  assert.ok(setup.some(row => row.option === "--dir" && row.target === "/tmp/home"));
  return { mounted, setup };
}

test("all admitted root shapes retain non-nested, creation-before-content setup", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-jail-layout-"));
  const a = directory(root, "a"), child = directory(a, "child"), sibling = directory(root, "ab");
  const read = directory(root, "read"), readChild = directory(read, "child"), readSibling = directory(root, "reader");
  const maximum = Array.from({ length: 32 }, (_, i) => directory(root, `root-${i}`));
  const cases: { project: string; writes: string[]; reads: string[]; expected: string[] }[] = [
    { project: a, writes: [], reads: [], expected: [a] },
    { project: a, writes: [a, child], reads: [], expected: [a] },
    { project: child, writes: [a], reads: [], expected: [a] },
    { project: a, writes: [sibling], reads: [read], expected: [a, sibling, read] },
    { project: sibling, writes: [child, a], reads: [readChild, read, readSibling], expected: [sibling, a, read, readSibling] },
    { project: a, writes: [], reads: ["/usr/bin", read, read], expected: [a, read] },
    { project: maximum[0]!, writes: maximum.slice(1, 16), reads: maximum.slice(16), expected: maximum },
  ];
  for (const [index, c] of cases.entries()) for (const allowNet of [false, true]) {
    const jail: NamespaceJailSpec = { mode: "required", projectDir: c.project,
      allowWritePaths: c.writes, readOnlyPaths: c.reads, allowNet,
      maxProcesses: 64, maxOpenFiles: 512, maxFileSizeBytes: 2047 };
    const plan = prepareRequiredJail("/usr/bin/true", [], jail, 10,
      { PATH: "/usr/bin:/bin", HOME: "/not-mounted", KEEP_LAYOUT_TEXT: "--dir\n/oldroot/not-an-option" }, Date.now() + 5000);
    try {
      const result = inspectLayout(plan.argumentBytes);
      assert.deepEqual(result.mounted, c.expected, `case${index}, allowNet=${allowNet}`);
    } finally { plan.close(); }
  }
});

test("explicit project roots under private tmp/home and run preserve setup ordering", () => {
  const jailUrl = new URL("../src/infra/required_project_jail.js", import.meta.url).href;
  const adapterUrl = new URL("../src/infra/process_isolation.js", import.meta.url).href;
  // Import the exact runtime BEFORE hiding /tmp in this disposable mount
  // namespace: an installed test consumer may itself live below the outer /tmp.
  // Neither /tmp nor /run is changed in the parent/host namespace.
  const code = `import assert from 'node:assert/strict';import fs from 'node:fs';import {execFileSync} from 'node:child_process';
import {prepareRequiredJail} from ${JSON.stringify(jailUrl)};
import {ProcessIsolationAdapter} from ${JSON.stringify(adapterUrl)};
assert.notEqual(fs.readlinkSync('/proc/self/ns/mnt'),process.argv[1]);
const mount=(args)=>execFileSync('mount',args,{timeout:3000});mount(['--make-rprivate','/']);
for(const p of ['/tmp','/run'])mount(['-t','tmpfs','-o','size=16m,mode=0755','tmpfs',p]);
for(const p of ['/tmp/home','/tmp/read','/run/project'])fs.mkdirSync(p);
fs.symlinkSync('/oldroot/run/project','/tmp/home/redirect');fs.writeFileSync('/tmp/read/input','42');
const jail={mode:'required',projectDir:'/tmp/home',allowWritePaths:['/run/project'],readOnlyPaths:['/tmp/read']};
const plan=prepareRequiredJail('/usr/bin/true',[],jail,undefined,{},Date.now()+5000);
const args=plan.argumentBytes.toString('base64');plan.close();
const result=await new ProcessIsolationAdapter().run(process.execPath,['-e',
'const fs=require("node:fs"),a=require("node:assert/strict");fs.writeFileSync("/tmp/home/useful","42");fs.writeFileSync("/run/project/useful","42");a.equal(fs.readFileSync("/tmp/read/input","utf8"),"42");a.throws(()=>fs.mkdirSync("/tmp/home/redirect/created"));'],
{cwd:'/tmp/home',timeoutMs:5000,namespaceJail:jail});
assert.equal(result.code,0,JSON.stringify(result));assert.equal(result.processIsolation.namespaceSetup,'launcher-confirmed');
assert.equal(fs.readFileSync('/tmp/home/useful','utf8'),'42');assert.equal(fs.readFileSync('/run/project/useful','utf8'),'42');
assert.equal(fs.existsSync('/run/project/created'),false);console.log(JSON.stringify({args,result:'PASS'}));`;
  const output = execFileSync("unshare", ["-Urm", process.execPath, "--input-type=module", "-e", code, readlinkSync("/proc/self/ns/mnt")], {
    encoding: "utf8", timeout: 15000, maxBuffer: 65536 });
  const result = JSON.parse(output) as { args: string; result: string };
  assert.equal(result.result, "PASS");
  assert.deepEqual(inspectLayout(Buffer.from(result.args, "base64")).mounted, ["/tmp/home", "/run/project", "/tmp/read"]);
});

test("read/write descendant destinations and symlink-root aliases refuse before launch", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-jail-layout-refuse-"));
  const project = directory(root, "project"), child = directory(project, "child");
  const alias = join(root, "alias"); symlinkSync(project, alias);
  for (const jail of [
    { projectDir: project, readOnlyPaths: [child] },
    { projectDir: child, readOnlyPaths: [project] },
    { projectDir: project, readOnlyPaths: [project] },
    { projectDir: alias },
  ]) assert.throws(() => prepareRequiredJail("/usr/bin/true", [], { mode: "required", ...jail }, undefined, {}, Date.now() + 5000),
    /overlap|canonical directory/u);
});

test("malicious setup symlinks in all supplied roots leave owned outside files unchanged", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-jail-layout-effects-"));
  const project = directory(root, "project"), scratch = directory(root, "project-sibling"), read = directory(root, "read");
  const victim = directory(root, "outside"); writeFileSync(join(victim, "original"), "unchanged");
  for (const path of [project, scratch, read]) {
    symlinkSync("/oldroot" + victim, join(path, "redirect"));
    writeFileSync(join(path, "input"), "42");
  }
  const result = await new ProcessIsolationAdapter().run(process.execPath, ["-e", `const fs=require('node:fs'),a=require('node:assert/strict');
fs.writeFileSync(${JSON.stringify(join(project, "useful"))},'42');fs.writeFileSync(${JSON.stringify(join(scratch, "useful"))},'42');
a.equal(fs.readFileSync(${JSON.stringify(join(read, "input"))},'utf8'),'42');
for(const path of ${JSON.stringify([project, scratch, read])})a.throws(()=>fs.mkdirSync(path+'/redirect/created'));
console.log('useful bounded task');`], { cwd: project, timeoutMs: 5000,
    namespaceJail: { mode: "required", projectDir: project, allowWritePaths: [scratch], readOnlyPaths: [read] } });
  assert.equal(result.code, 0, JSON.stringify(result));
  assert.equal(result.processIsolation?.namespaceSetup, "launcher-confirmed");
  assert.equal(result.stdout.trim(), "useful bounded task");
  assert.deepEqual(readdirSync(victim), ["original"]); assert.equal(readFileSync(join(victim, "original"), "utf8"), "unchanged");
  for (const path of [project, scratch]) assert.equal(readFileSync(join(path, "useful"), "utf8"), "42");
});
