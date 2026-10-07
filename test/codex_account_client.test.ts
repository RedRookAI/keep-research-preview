import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CodexAccountClient, CodexAccountError, type CodexAccountRequest } from "../src/gateway/codex_account_client.js";

function fixture(mode: string) {
  const root = mkdtempSync(join(tmpdir(), "keep-codex-client-test-"));
  const executable = join(root, "codex-fixture"), record = join(root, "record.json");
  const script = `#!${process.execPath}
import fs from 'node:fs';
const args=process.argv.slice(2),record=${JSON.stringify(record)},mode=${JSON.stringify(mode)};
let input='';process.stdin.on('data',b=>{input+=b});process.stdin.on('end',()=>{
 fs.writeFileSync(record,JSON.stringify({args,input,apiKey:process.env.OPENAI_API_KEY??null,codexKey:process.env.CODEX_API_KEY??null}));
 const send=x=>process.stdout.write(JSON.stringify(x)+'\\n');
 send({type:'thread.started',thread_id:'owned-fixture'});send({type:'turn.started'});
 if(mode==='timeout'||mode==='cancel'){setInterval(()=>{},1000);return;}
 if(mode==='tool'){send({type:'item.started',item:{type:'command_execution',command:'never executed by fixture'}});return;}
 if(mode==='malformed'){process.stdout.write('not-json\\n');return;}
 if(mode==='overflow'){process.stdout.write('x'.repeat(20000));return;}
 send({type:'item.completed',item:{type:'agent_message',text:'preparing a final answer'}});
 send({type:'item.completed',item:{type:'agent_message',text:JSON.stringify({text:'a real-looking fixture response — not model evidence'})}});
 if(mode==='usage-missing')send({type:'turn.completed'});
 else send({type:'turn.completed',usage:{input_tokens:9,cached_input_tokens:mode==='usage-invalid'?10:2,output_tokens:4}});
 if(mode==='late-error')send({type:'error',message:'late failure'});
});
`;
  writeFileSync(executable, script, { mode: 0o700 });
  const client = new CodexAccountClient({ executable, model: "fixture-model", maxSubmittedPromptBytes: 4096, maxCapturedOutputBytes: 4096, maxElapsedMs: mode === "timeout" ? 80 : 2000 });
  return { root, record, client };
}

test("Codex transport preserves explicit subscription provenance, arguments and observed usage", async () => {
  const f = fixture("success");
  const oldApiKey = process.env["OPENAI_API_KEY"], oldCodexKey = process.env["CODEX_API_KEY"];
  process.env["OPENAI_API_KEY"] = "owned-test-sentinel-not-a-key";
  process.env["CODEX_API_KEY"] = "owned-test-sentinel-not-a-key";
  try {
    const result = await f.client.generate({ billingBasis: "chatgpt-subscription", prompt: "Return a proposal" });
    assert.equal(f.client.isLocal, false); assert.equal(result.billingBasis, "chatgpt-subscription");
    assert.equal(result.allocatedPlanCostUsd, null); assert.equal(result.modelWireAttempts, null); assert.equal(result.reportedModel, null);
    assert.deepEqual(result.usage, { inputTokens: 9, cachedInputTokens: 2, outputTokens: 4 });
    const record = JSON.parse(readFileSync(f.record, "utf8"));
    assert.equal(record.apiKey, null); assert.equal(record.codexKey, null);
    assert.ok(record.args.includes("--ignore-user-config") && record.args.includes("--ephemeral"));
    assert.ok(record.args.includes('forced_login_method="chatgpt"'));
    assert.ok(!record.args.some((arg: string) => arg.startsWith("model_providers.openai.")), "built-in provider IDs cannot be overridden");
    assert.equal(record.args[record.args.indexOf("--sandbox") + 1], "read-only");
    assert.ok(record.args.includes("features.shell_tool=false") && record.args.includes("features.unified_exec=false"));
    assert.match(record.input, /Return a proposal/u);
  } finally {
    if (oldApiKey === undefined) delete process.env["OPENAI_API_KEY"]; else process.env["OPENAI_API_KEY"] = oldApiKey;
    if (oldCodexKey === undefined) delete process.env["CODEX_API_KEY"]; else process.env["CODEX_API_KEY"] = oldCodexKey;
    rmSync(f.root, { recursive: true, force: true });
  }
});

test("unsupported hard bounds, oversized submitted prompt and cancellation refuse before dispatch", async () => {
  const f = fixture("success"), controller = new AbortController(); controller.abort();
  try {
    for (const request of [{ prompt: "p", hardOutputTokenLimit: 10 }, { prompt: "p", hardModelWireAttemptLimit: 1 }, { prompt: "p", hardModelInputByteLimit: 10 },
      { prompt: "x".repeat(4096) }, { prompt: "p", signal: controller.signal }])
      await assert.rejects(f.client.generate({ billingBasis: "chatgpt-subscription", ...request }), (e: unknown) => e instanceof CodexAccountError && e.dispatch === "not-started");
    const apiRequest = { prompt: "p", maxTokens: 10, maxAttempts: 1 };
    await assert.rejects(f.client.generate(apiRequest as unknown as CodexAccountRequest), (e: unknown) => e instanceof CodexAccountError && e.dispatch === "not-started");
    await assert.rejects(f.client.generate({ prompt: "p" } as CodexAccountRequest), (e: unknown) => e instanceof CodexAccountError && e.dispatch === "not-started");
    assert.equal(existsSync(f.record), false);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});

for (const mode of ["tool", "malformed", "overflow", "usage-missing", "usage-invalid", "late-error", "timeout"])
  test(`entered Codex ${mode} failure retains uncertainty instead of inventing zero work`, async () => {
    const f = fixture(mode);
    try {
      await assert.rejects(f.client.generate({ billingBasis: "chatgpt-subscription", prompt: "p" }), (e: unknown) => e instanceof CodexAccountError && e.dispatch === "entered");
    } finally { rmSync(f.root, { recursive: true, force: true }); }
  });

test("cancellation after a live invocation began remains entered work", async () => {
  const f = fixture("cancel"), controller = new AbortController();
  const pending = f.client.generate({ billingBasis: "chatgpt-subscription", prompt: "p", signal: controller.signal });
  void pending.catch(() => {});
  try {
    for (let attempt = 0; attempt < 200 && !existsSync(f.record); attempt++)
      await new Promise(resolve => setTimeout(resolve, 5));
    assert.equal(existsSync(f.record), true, "the controlled child must have actually entered");
    controller.abort();
    await assert.rejects(pending, (e: unknown) => e instanceof CodexAccountError && e.dispatch === "entered");
  } finally { controller.abort(); rmSync(f.root, { recursive: true, force: true }); }
});
