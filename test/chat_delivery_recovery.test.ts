import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHmac } from "node:crypto";
import { mkdtempSync, appendFileSync, readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { ChatDeliveryStore, ChatDeliveryCapacityError, deliveryDigest } from "../src/channel/chat_delivery_store.js";
import { NODE_IO } from "../src/spine/durable_fs.js";
import { once } from "node:events";

const SECRET = "owned-replay-fixture", WINDOW = 300_000, INITIAL = 1_760_000_000_000;
async function fixture(mode: "ok" | "lost" | "reject" | "malformed" = "ok", maxRecords?: number) {
  const root = mkdtempSync(join(tmpdir(), "keep-replay-identity-")), outbox = join(root, "outbox.jsonl"), replayFile = join(root, "replay.jsonl");
  const sink = createServer(async (req, res) => {
    let raw = ""; for await (const chunk of req) raw += chunk;
    appendFileSync(outbox, JSON.stringify({ path: req.url, raw }) + "\n");
    if (mode === "lost") { req.socket.destroy(); return; }
    res.writeHead(mode === "reject" ? 503 : 200, { "content-type": "application/json" }); if (mode === "malformed") { res.end("not-json"); return; } res.end(req.url === "/projects" ? '{"projects":[]}' : '{"accepted":true}');
  });
  sink.listen(0, "127.0.0.1"); await once(sink, "listening");
  const address = sink.address(); assert.ok(address && typeof address === "object");
  const port = address.port;
  const children: ChildProcess[] = [];
  const count = () => { try { return readFileSync(outbox, "utf8").trim().split("\n").filter(Boolean).length; } catch { return 0; } };
  async function start(now = INITIAL, faultJournalSync?: number) {
    const moduleUrl = new URL("../src/channel/chat_server.js", import.meta.url).href;
    const script = `Date.now=()=>${now}; process.on("message",m=>{ if(m.type==="clock"){Date.now=()=>m.now; process.send({type:"clock"});} }); const adapter=await import(${JSON.stringify(moduleUrl)}); await adapter.main(); ${faultJournalSync === undefined ? "" : `const {NODE_IO}=await import(new URL("../spine/durable_fs.js", ${JSON.stringify(moduleUrl)})); const paths=new Map(); const open=NODE_IO.openSync, sync=NODE_IO.fsyncSync; let count=0; NODE_IO.openSync=(p,f)=>{const fd=open(p,f); paths.set(fd,p); return fd;}; NODE_IO.fsyncSync=fd=>{if(paths.get(fd)?.includes(".delivery-v1.json.") && paths.get(fd)?.endsWith(".tmp") && ++count===${faultJournalSync}) throw Object.assign(new Error("owned disk fault"),{code:"EIO"}); return sync(fd);};`}`;
    const env: NodeJS.ProcessEnv = { ...process.env, KEEP_GATEWAY_ORIGIN: `http://127.0.0.1:${port}`, KEEP_GATEWAY_TOKEN: "owned-gateway", KEEP_CHAT_SECRET: SECRET, KEEP_CHAT_REPLAY_FILE: replayFile, KEEP_CHAT_PORT: "0", ...(maxRecords === undefined ? {} : { KEEP_CHAT_DELIVERY_MAX_RECORDS: String(maxRecords) }) }; delete env["NODE_TEST_CONTEXT"];
    const child = spawn(process.execPath, ["--input-type=module", "--eval", script], { env, stdio: ["ignore", "pipe", "pipe", "ipc"] }); children.push(child);
    let stdout = "", stderr = ""; child.stderr?.on("data", data => { stderr += data; });
    const closed = new Promise<void>(resolve => child.once("close", () => resolve()));
    const origin = await new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("owned adapter startup deadline")); }, 3_000);
      child.once("error", error => { clearTimeout(timer); reject(error); });
      child.once("exit", code => { clearTimeout(timer); reject(new Error(`adapter exited ${code}: ${stderr}`)); });
      child.stdout?.on("data", data => { stdout += data; if (!stdout.includes("\n")) return; clearTimeout(timer); const ready = JSON.parse(stdout.split("\n")[0]!); resolve(`http://${ready.host}:${ready.port}`); });
    });
    return { child, origin, async clock(next: number) { const ack = once(child, "message"); child.send({ type: "clock", now: next }); await ack; }, async stop() { child.kill("SIGTERM"); await closed; } };
  }
  async function send(origin: string, raw: string, timestamp: number | string, id: string, valid = true) {
    const signature = createHmac("sha256", SECRET).update(`${Number(timestamp)}.${raw}`).digest("hex");
    const response = await fetch(`${origin}/event`, { method: "POST", headers: { "content-type": "application/json", "x-webhook-id": id, "x-webhook-timestamp": String(timestamp), "x-webhook-signature": `sha256=${valid ? signature : "0".repeat(64)}` }, body: raw });
    const body = await response.text(); return { status: response.status, body };
  }
  async function cleanup() {
    for (const child of children) if (child.exitCode === null && child.signalCode === null) { const closed = once(child, "close"); child.kill("SIGKILL"); await closed; }
    await new Promise<void>((resolve, reject) => sink.close(error => error ? reject(error) : resolve()));
    rmSync(root, { recursive: true, force: true });
  }
  return { root, replayFile, outbox, count, start, send, cleanup };
}

const raw = JSON.stringify({ kind: "project", goal: "owned journal operation", eventId: "owner-1" });
function journal(file: string): { rows: Array<{ id: string; state: string; ack?: { status: number; bodySha256: string } }> } { return JSON.parse(readFileSync(`${file}.delivery-v1.json`, "utf8")); }

test("eligible acknowledgment confirms durable gateway acceptance and duplicate has retained state", { timeout: 10_000 }, async () => {
 const f = await fixture(); try { const a = await f.start(); assert.equal((await f.send(a.origin, raw, INITIAL / 1000, "first")).status, 200);
 const rows = journal(f.replayFile).rows; assert.equal(rows.length, 1); assert.equal(rows[0]!.state, "confirmed"); assert.equal(rows[0]!.ack!.status, 200); assert.match(rows[0]!.ack!.bodySha256, /^[a-f0-9]{64}$/);
 const duplicate = await f.send(a.origin, raw, INITIAL / 1000, "changed"); assert.equal(duplicate.status, 409); assert.equal(JSON.parse(duplicate.body).deliveryState, "confirmed"); assert.equal(f.count(), 1);
 } finally { await f.cleanup(); }
});

test("invalid signed event creates no accepted delivery", { timeout: 10_000 }, async () => {
 const f = await fixture(); try { const a = await f.start(); assert.equal((await f.send(a.origin, '{"kind":"invalid"}', INITIAL / 1000, "bad-event")).status, 400);
 assert.equal(journal(f.replayFile).rows.length, 0); assert.equal(f.count(), 0);
 } finally { await f.cleanup(); }
});

test("sink commit followed by lost acknowledgment stays unresolved across restart and expiry", { timeout: 10_000 }, async () => {
 const f = await fixture("lost"); try { let a = await f.start(); assert.equal((await f.send(a.origin, raw, INITIAL / 1000, "first")).status, 502);
 assert.equal(f.count(), 1); assert.equal(journal(f.replayFile).rows[0]!.state, "unknown"); await a.stop(); a = await f.start();
 const duplicate = await f.send(a.origin, raw, INITIAL / 1000, "restart"); assert.equal(duplicate.status, 409); assert.equal(JSON.parse(duplicate.body).deliveryState, "unknown"); assert.equal(f.count(), 1);
 await a.stop(); a = await f.start(INITIAL + 3 * WINDOW); assert.equal(journal(f.replayFile).rows[0]!.state, "unknown"); assert.equal(f.count(), 1);
 } finally { await f.cleanup(); }
});

test("two actual adapter processes sharing a journal admit one dispatch", { timeout: 10_000 }, async () => {
 const f = await fixture(); try { const a = await f.start(), b = await f.start();
 const results = await Promise.all([f.send(a.origin, raw, INITIAL / 1000, "owner"), f.send(b.origin, raw, INITIAL / 1000, "tenant-a")]);
 assert.deepEqual(results.map(r => r.status).sort(), [200,409]); assert.equal(f.count(), 1); assert.equal(journal(f.replayFile).rows.length, 1);
 } finally { await f.cleanup(); }
});


test("disk failure before entered publication permits no sink entry; proven intent can be retried", { timeout: 10_000 }, async () => {
 for (const failAt of [1, 2]) { const f = await fixture(); try { const a = await f.start(INITIAL, failAt);
 assert.equal((await f.send(a.origin, raw, INITIAL / 1000, "disk-fault")).status, 500); assert.equal(f.count(), 0);
 assert.deepEqual(journal(f.replayFile).rows.map(r => r.state), failAt === 1 ? [] : ["intent"]);
 assert.equal((await f.send(a.origin, raw, INITIAL / 1000, "retry-unentered")).status, 200); assert.equal(f.count(), 1); assert.equal(journal(f.replayFile).rows[0]!.state, "confirmed");
 } finally { await f.cleanup(); } }
});

test("actual process death after sink commit retains entered state and prevents restart dispatch", { timeout: 10_000 }, async () => {
 const f = await fixture("lost"); try { const a = await f.start();
 // Drop the owned child while the sink has committed but before the lost response resolves.
 const pending = f.send(a.origin, raw, INITIAL / 1000, "death").catch(() => undefined);
 while (f.count() === 0) await new Promise(resolve => setTimeout(resolve, 1));
 const closed = once(a.child, "close"); a.child.kill("SIGKILL"); await closed; await pending;
 assert.ok(["entered","unknown"].includes(journal(f.replayFile).rows[0]!.state)); const b = await f.start();
 assert.equal((await f.send(b.origin, raw, INITIAL / 1000, "restart")).status, 409); assert.equal(f.count(), 1);
 } finally { await f.cleanup(); }
});

function key(label: string): string { return "keep-chat-envelope/v2:" + deliveryDigest(label); }
test("finite record/byte limits retain unknown state beyond expiry and require evidence-bound reconciliation", () => {
 for (const limits of [{ maxRecords: 1, maxBytes: 8192 }, { maxRecords: 100, maxBytes: 600 }]) {
  const root = mkdtempSync(join(tmpdir(), "keep-delivery-capacity-")), file = join(root, "replay");
  try {
   const store = new ChatDeliveryStore(file, limits), id = key("owner"), claim = store.claimForEntry(id, INITIAL + WINDOW, INITIAL); assert.ok(claim.admitted); store.finish(id, claim.token);
   const before = readFileSync(store.file, "utf8");
   assert.throws(() => store.claimForEntry(key("organization-a"), INITIAL + 4 * WINDOW, INITIAL + 3 * WINDOW), ChatDeliveryCapacityError);
   assert.equal(readFileSync(store.file, "utf8"), before); assert.equal(journal(file).rows[0]!.state, "unknown");
   assert.throws(() => store.reconcile(id, "no-effect", "not-evidence")); assert.equal(readFileSync(store.file, "utf8"), before);
   store.reconcile(id, "no-effect", deliveryDigest("independently checked owned sink evidence"));
   assert.equal(journal(file).rows[0]!.state, "reconciled"); assert.ok(store.claimForEntry(key("organization-a"), INITIAL + 4 * WINDOW, INITIAL + 3 * WINDOW).admitted);
  } finally { rmSync(root, { recursive: true, force: true }); }
 }
 for (const invalid of [0,-1,1.5,NaN,Infinity,Number.MAX_SAFE_INTEGER+1]) { const root=mkdtempSync(join(tmpdir(), "keep-delivery-limit-")); try { for(const field of ["maxRecords","maxBytes"]) assert.throws(()=>new ChatDeliveryStore(join(root,"replay"),{[field]:invalid}), /positive finite safe/); } finally { rmSync(root,{recursive:true,force:true}); } }
});

test("old/corrupt/oversized journal and changed replay state preserve bytes and refuse entry", () => {
 const root = mkdtempSync(join(tmpdir(), "keep-delivery-integrity-")), file = join(root, "replay");
 try {
  const store = new ChatDeliveryStore(file), original = readFileSync(store.file, "utf8");
  for (const damaged of ["{bad-json", '{"schema":"old","rows":[]}', original.replace('"rows":[]', '"rows":[{}]'), "x".repeat(1025)]) {
   writeFileSync(store.file, damaged); assert.throws(()=>new ChatDeliveryStore(file, {maxBytes:1024})); assert.equal(readFileSync(store.file,"utf8"),damaged);
  }
  writeFileSync(store.file,original); appendFileSync(`${file}.authenticated-v2.jsonl`, "\n"); assert.throws(()=>store.claimForEntry(key("new"),INITIAL+WINDOW,INITIAL),/changed/); assert.equal(readFileSync(store.file,"utf8"),original);
 } finally { rmSync(root,{recursive:true,force:true}); }
});

test("T005 authenticated keys migrate as unknown without deleting original state", () => {
 const root=mkdtempSync(join(tmpdir(),"keep-delivery-import-")),file=join(root,"replay"),sidecar=`${file}.authenticated-v2.jsonl`,id=key("old-admission");
 try { const legacy=JSON.stringify({schema:"keep.chat-replay/v2"})+"\n"+JSON.stringify({id,expiresAt:INITIAL+WINDOW})+"\n";writeFileSync(sidecar,legacy);
 const store=new ChatDeliveryStore(file);assert.equal(readFileSync(sidecar,"utf8"),legacy);assert.deepEqual(store.claimForEntry(id,INITIAL+WINDOW,INITIAL),{admitted:false,state:"unknown"});assert.equal(journal(file).rows[0]!.state,"unknown");
 assert.throws(()=>store.finish(id,"f".repeat(64),{status:200,bodySha256:deliveryDigest("ack")}),/does not own/);
 } finally {rmSync(root,{recursive:true,force:true});}
});

test("journal publications fsync data then directory and keep only bounded acknowledgment metadata", () => {
 const root=mkdtempSync(join(tmpdir(),"keep-delivery-flush-")),file=join(root,"replay"),store=new ChatDeliveryStore(file),paths=new Map<number,string>(),trace:string[]=[];
 const open=NODE_IO.openSync,sync=NODE_IO.fsyncSync;
 try {NODE_IO.openSync=(p,f)=>{const fd=open(p,f);paths.set(fd,p);return fd;};NODE_IO.fsyncSync=fd=>{trace.push(paths.get(fd)??"unknown");return sync(fd);};
 const claim=store.claimForEntry(key("flush"),INITIAL+WINDOW,INITIAL);assert.ok(claim.admitted);store.finish(key("flush"),claim.token,{status:200,bodySha256:deliveryDigest("x".repeat(1024*1024))});
 const publications=trace.filter(p=>p.includes(".delivery-v1.json.")&&p.endsWith(".tmp"));assert.equal(publications.length,3);
 for(const temp of publications){const i=trace.indexOf(temp);assert.equal(trace[i+1],root);}
 const bytes=readFileSync(store.file,"utf8");assert.ok(Buffer.byteLength(bytes)<1000);assert.equal(bytes.includes("xxxx"),false);assert.equal(journal(file).rows[0]!.state,"confirmed");
 } finally {NODE_IO.openSync=open;NODE_IO.fsyncSync=sync;rmSync(root,{recursive:true,force:true});}
});


test("full actual adapter journal refuses a new scoped intent without dropping unknown effects", { timeout: 10_000 }, async () => {
 const f=await fixture("lost",1);try{const a=await f.start();assert.equal((await f.send(a.origin,raw,INITIAL/1000,"owner")).status,502);
 const before=readFileSync(`${f.replayFile}.delivery-v1.json`,"utf8");const other=JSON.stringify({kind:"project",goal:"tenant operation",eventId:"organization-a"});
 assert.equal((await f.send(a.origin,other,INITIAL/1000,"tenant")).status,503);assert.equal(f.count(),1);assert.equal(readFileSync(`${f.replayFile}.delivery-v1.json`,"utf8"),before);
 }finally{await f.cleanup();}
});


test("noneligible acknowledgment and malformed successful body retain uncertainty", { timeout: 10_000 }, async () => {
 for(const mode of ["reject","malformed"] as const){const f=await fixture(mode);try{const a=await f.start();assert.equal((await f.send(a.origin,raw,INITIAL/1000,"first")).status,502);assert.equal(f.count(),1);assert.equal(journal(f.replayFile).rows[0]!.state,"unknown");assert.equal((await f.send(a.origin,raw,INITIAL/1000,"second")).status,409);assert.equal(f.count(),1);}finally{await f.cleanup();}}
});


test("installed reconciliation command requires evidence and never redispatches", { timeout: 10_000 }, async () => {
 const f=await fixture("lost");try{const a=await f.start();assert.equal((await f.send(a.origin,raw,INITIAL/1000,"first")).status,502);await a.stop();
 const id=journal(f.replayFile).rows[0]!.id,before=readFileSync(`${f.replayFile}.delivery-v1.json`,"utf8"),module=new URL("../src/channel/chat_server.js",import.meta.url);
 const env:NodeJS.ProcessEnv={...process.env,KEEP_CHAT_REPLAY_FILE:f.replayFile};delete env["NODE_TEST_CONTEXT"];
 const invoke=(evidence:string)=>spawnSync(process.execPath,[module.pathname,"--reconcile-delivery",id,"no-effect",evidence],{env,encoding:"utf8",timeout:3000,maxBuffer:1024*1024});
 const invalid=invoke("missing-evidence");assert.equal(invalid.status,1);assert.equal(readFileSync(`${f.replayFile}.delivery-v1.json`,"utf8"),before);
 const valid=invoke(deliveryDigest("owned sink inspected by fixture"));assert.equal(valid.status,0,valid.stderr);assert.match(valid.stdout,/no redispatch performed/);assert.equal(journal(f.replayFile).rows[0]!.state,"reconciled");assert.equal(f.count(),1);
 }finally{await f.cleanup();}
});
