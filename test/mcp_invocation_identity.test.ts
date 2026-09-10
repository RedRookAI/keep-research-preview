import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { CapabilityHub, capabilityInvocationDigest, captureCapabilityInvocation } from "../src/ecosystem/capability_port.js";
import { ReferenceMonitor, neverEvent, type TraceEvent } from "../src/control/reference_monitor.js";
import { HostileMcpGateway, type ToolDefinition } from "../src/ecosystem/hostile_mcp_gateway.js";
import { McpServerAdapter, MCP_PROTOCOL_VERSION, type McpTransport } from "../src/ecosystem/mcp.js";

// Trusted in-process caller/transport reproduction, not a remote exploit. The
// journal records actual transport entry, independently of adapter return values.
function fixture(referenceMonitor?: ReferenceMonitor) {
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-mcp-identity-"))), new InProcessLock(), new SchemaRegistry());
  const gateway = new HostileMcpGateway({ spine, ...(referenceMonitor ? { referenceMonitor } : {}) });
  let definitions: ToolDefinition[] = [
    { name: "fs.read", description: "Read a synthetic file" },
    { name: "db.drop", description: "Drop a synthetic database" },
  ];
  const calls: { name: string; args: unknown; meta: unknown; frozen: boolean }[] = [];
  let lookups = 0;
  let lookupBarrier: Promise<void> | undefined;
  const transport: McpTransport = {
    serverProtocolVersion: MCP_PROTOCOL_VERSION, requiresOAuth: true,
    listTools: async () => definitions.map(d => d.name),
    listToolDefinitions: async () => { lookups++; await lookupBarrier; return definitions; },
    callTool: async (name, args, meta) => {
      calls.push({ name, args: JSON.parse(JSON.stringify(args)), meta, frozen: Object.isFrozen(args) });
      return { completed: name };
    },
  };
  const adapter = new McpServerAdapter("mcp", "synthetic", "fixture", transport, "untrusted", gateway);
  const hub = new CapabilityHub(spine); hub.register(adapter);
  return {
    adapter, hub, calls, get lookups() { return lookups; },
    pause() { let release!: () => void; lookupBarrier = new Promise<void>(resolve => { release = resolve; }); return release; },
    changeDefinition() { definitions = definitions.map(d => ({ ...d, description: d.description + " changed" })); },
  };
}

test("KEEP-12C-003: direct MCP dispatch retains the operation and nested arguments captured before lookup", async () => {
  const f = fixture(); await f.adapter.approveTool("fs.read", "owner");
  const release = f.pause();
  const inv = { capabilityId: "mcp", operation: "fs.read", args: { target: { path: "safe" } }, traceparent: "original-trace" };
  const pending = f.adapter.invoke(inv);
  inv.operation = "unapproved_write";
  inv.args.target.path = "changed";
  inv.traceparent = "changed-trace";
  release();
  assert.equal((await pending).ok, true, "the originally approved useful request should still run");
  assert.equal(f.lookups, 2, "one approval lookup and one invocation lookup");
  assert.deepEqual(f.calls.map(({ name, args, meta }) => ({ name, args, meta })), [
    { name: "fs.read", args: { target: { path: "safe" } }, meta: { traceparent: "original-trace" } },
  ]);
});

test("direct MCP cannot acquire human approval by changing context during definition lookup", async () => {
  const f = fixture(); await f.adapter.approveTool("db.drop", "owner");
  const release = f.pause();
  const context = { effect: "destructive" as const, authorized: false };
  const pending = f.adapter.invoke({ capabilityId: "mcp", operation: "db.drop", args: {} }, context);
  context.authorized = true; release();
  const result = await pending;
  assert.equal(result.ok, false); assert.equal(result.held, true);
  assert.equal(f.calls.length, 0);
  assert.equal((await f.adapter.invoke({ capabilityId: "mcp", operation: "db.drop", args: {} }, { effect: "destructive", authorized: true })).ok, true);
  assert.equal(f.calls.length, 1, "explicit approval remains useful");
});

test("the normal hub already protects MCP inputs; changed definitions still quarantine the tool", async () => {
  const f = fixture(); await f.adapter.approveTool("fs.read", "owner");
  const release = f.pause();
  const inv = { capabilityId: "mcp", operation: "fs.read", args: { paths: ["safe"] } };
  const pending = f.hub.invoke(inv);
  inv.operation = "unapproved_write"; inv.args.paths[0] = "changed"; release();
  assert.equal((await pending).ok, true);
  assert.equal(f.calls[0]!.name, "fs.read");
  assert.deepEqual(f.calls[0]!.args, { paths: ["safe"] });
  f.changeDefinition();
  const changed = await f.adapter.invoke({ capabilityId: "mcp", operation: "fs.read", args: {} });
  assert.equal(changed.ok, false); assert.match(changed.error ?? "", /definition changed/);
  assert.equal(f.calls.length, 1);
});

test("direct MCP rejects non-object, cyclic, oversized and overdeep arguments before definition lookup", async () => {
  const f = fixture(); await f.adapter.approveTool("fs.read", "owner");
  const cyclic: Record<string, unknown> = {}; cyclic["self"] = cyclic;
  let deep: Record<string, unknown> = {};
  for (let i = 0; i < 130; i++) deep = { next: deep };
  const invalid: unknown[] = [null, [], "text", cyclic, { value: 1n },
    { text: "x".repeat(1024 * 1024) }, deep,
    { toJSON: () => [] }, { toJSON: () => undefined }];
  const before = f.lookups;
  for (const args of invalid) {
    const result = await f.adapter.invoke({ capabilityId: "mcp", operation: "fs.read", args: args as Record<string, unknown> });
    assert.equal(result.ok, false);
    assert.equal(result.error, "MCP invocation input is invalid");
  }
  assert.equal(f.lookups, before, "invalid input never starts definition lookup");
  assert.equal(f.calls.length, 0);
  assert.equal((await f.adapter.invoke({ capabilityId: "mcp", operation: "fs.read", args: { text: "二", nested: [1, true, null] } })).ok, true);
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0]!.frozen, true);
});

test("capture preserves JSON semantics, reads invocation args once and keeps the captured property bag", () => {
  let reads = 0;
  const inv = { capabilityId: "mcp", operation: "fs.read", auditArgs: "digest" as const,
    get args() { reads++; return { paths: ["safe"], omitted: undefined, array: [undefined, NaN] }; } };
  const first = captureCapabilityInvocation(inv);
  assert.equal(reads, 1);
  assert.equal(first.auditArgs, "digest");
  assert.deepEqual(first.args, { paths: ["safe"], array: [null, null] });
  assert.deepEqual(captureCapabilityInvocation(first), first, "hub-to-adapter recapture preserves JSON values");
});

test("a trusted serializer cannot grant itself human approval; its error text is not returned", async () => {
  const f = fixture(); await f.adapter.approveTool("db.drop", "owner");
  const context = { effect: "destructive" as const, authorized: false };
  const result = await f.adapter.invoke({ capabilityId: "mcp", operation: "db.drop",
    args: { toJSON: () => { context.authorized = true; return {}; } } }, context);
  assert.equal(result.ok, false); assert.equal(result.held, true);
  assert.equal(f.calls.length, 0);
  const bad = await f.adapter.invoke({ capabilityId: "mcp", operation: "db.drop", args: { toJSON: () => { throw Error("private serializer detail"); } } });
  assert.deepEqual(bad, { ok: false, error: "MCP invocation input is invalid" });
});

test("reference monitor observes captured arguments; a mutating monitor refuses before transport", async () => {
  let mode: "observe" | "mutate" = "observe";
  const seen: unknown[] = [];
  const monitor = new ReferenceMonitor();
  monitor.register(neverEvent("fixture", "observe the checked request", (event: TraceEvent) => {
    const payload = event.payload as { args: { target: { path: string } } };
    seen.push(JSON.parse(JSON.stringify(payload.args)));
    if (mode === "mutate") payload.args.target.path = "changed-by-monitor";
    return false;
  }));
  const f = fixture(monitor); await f.adapter.approveTool("fs.read", "owner");
  const release = f.pause();
  const inv = { capabilityId: "mcp", operation: "fs.read", args: { target: { path: "safe" } } };
  const pending = f.adapter.invoke(inv); inv.args.target.path = "caller-change"; release();
  assert.equal((await pending).ok, true);
  assert.deepEqual(seen, [{ target: { path: "safe" } }]);
  assert.deepEqual(f.calls[0]!.args, seen[0]);
  mode = "mutate";
  const refused = await f.adapter.invoke({ capabilityId: "mcp", operation: "fs.read", args: { target: { path: "safe" } } });
  assert.equal(refused.ok, false); assert.equal(refused.held, undefined);
  assert.match(refused.error ?? "", /read only|read-only|readonly/i);
  assert.equal(f.calls.length, 1, "monitor mutation does not produce a second dispatch");
});

for (const tenant of [undefined, "alpha"] as const) {
  test(`shared capture preserves ${tenant ?? "personal"} fleet digest, deep immutability and live cancellation signal`, async () => {
    const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-capture-fleet-"))), new InProcessLock(), new SchemaRegistry());
    const hub = new CapabilityHub(spine);
    const controller = new AbortController();
    const inv = { capabilityId: "synthetic", operation: "fs.read", args: { paths: ["original"] }, signal: controller.signal };
    const descriptor = { id: "synthetic", kind: "connector" as const, name: "fixture", credentialId: "unused", trust: "verified" as const, ...(tenant === undefined ? {} : { tenant }) };
    const expectedDigest = capabilityInvocationDigest(inv, descriptor, tenant);
    const permit = { operationId: "one", tenant: tenant ?? "keep.n1.default", agent: "fixture", admissionDigest: "fixture", effectDigest: expectedDigest };
    let release!: () => void;
    const barrier = new Promise<void>(r => { release = r; });
    let dispatches = 0;
    hub.installFleetPermitVerifier(async (capturedPermit, digest) => {
      await barrier;
      assert.equal(capturedPermit.operationId, "one");
      assert.equal(digest, expectedDigest);
      return true;
    });
    hub.register({ descriptor, invoke: async (captured, context) => {
      dispatches++;
      assert.equal(captured.operation, "fs.read");
      assert.deepEqual(captured.args, { paths: ["original"] });
      assert.equal(Object.isFrozen(captured), true);
      assert.equal(Object.isFrozen(captured.args["paths"]), true);
      assert.equal(captured.signal, controller.signal);
      assert.equal(captured.signal?.aborted, true, "signal remains live; capture does not claim cancellation enforcement");
      assert.equal(context?.fleetOperation?.effectDigest, expectedDigest);
      return { ok: true, output: "synthetic" };
    } });
    const pending = hub.invoke(inv, { fleetPermit: permit, ...(tenant === undefined ? {} : { tenant }) });
    inv.operation = "changed"; inv.args.paths[0] = "changed"; permit.operationId = "changed";
    controller.abort(); release();
    assert.equal((await pending).ok, true);
    assert.equal(dispatches, 1);
  });
}
