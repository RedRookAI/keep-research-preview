import { test } from "node:test";
import { execFileSync } from "node:child_process";

test("native inventory ordering retains exact units and rejects duplicate identities", () => {
  execFileSync(process.execPath, ["--input-type=module", "-e", `
    import assert from 'node:assert/strict';
    import { readFileSync } from 'node:fs';
    import { orderCompilationUnits } from './tools/native_compilation_units.mjs';
    const units=JSON.parse(readFileSync('native/p2-crypto-vendor-inventory.json','utf8')).compiledUnits;
    const original=JSON.stringify(units);
    assert.deepEqual(orderCompilationUnits(units),units);
    assert.deepEqual(orderCompilationUnits([...units].reverse()),units);
    assert.deepEqual(orderCompilationUnits([...units.slice(1),units[0]]),units);
    assert.equal(JSON.stringify(units),original);
    assert.throws(()=>orderCompilationUnits([...units,units[0]]),/duplicate/);
    assert.throws(()=>orderCompilationUnits([{unitId:''}]),/identity/);
    const changed=structuredClone(units);changed[0].outputs[0].sha256='changed';
    assert.notDeepEqual(orderCompilationUnits(changed),units);
  `], { cwd: process.cwd(), encoding: "utf8", timeout: 10000 });
});

test("native resolver trace accepts identity reads but refuses extra effects and absent observations", () => {
  execFileSync(process.execPath, ["--input-type=module", "-e", `
    import assert from 'node:assert/strict';
    import { assertResolverTrace } from './tools/native_resolver_trace.mjs';
    const base='42 execve("/resolver", ["/resolver"], 0x1 /* 0 vars */) = 0\\n42 getpid() = 42\\n42 geteuid() = 0\\n42 exit_group(0) = ?\\n';
    assert.doesNotThrow(()=>assertResolverTrace(base));
    for(const trace of ['', 'garbage', base+'42 socket(AF_INET, SOCK_STREAM, 0) = 3\\n',
      base+'42 open("/tmp/out", O_WRONLY|O_CREAT, 0600) = 3\\n',
      base+'42 openat2(3, "out", {flags=O_RDWR}, 24) = 4\\n',
      base+'42 open("/dev/kvm", O_RDONLY) = 3\\n',
      base+'42 execve("/second", [], 0x1) = 0\\n'])assert.throws(()=>assertResolverTrace(trace));
  `], { cwd: process.cwd(), encoding: "utf8", timeout: 10000 });
});
