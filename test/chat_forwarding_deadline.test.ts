import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type ServerResponse } from "node:http";
import { createHmac } from "node:crypto";
import { mkdtempSync, appendFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import type { Socket } from "node:net";
const SECRET = "owned-deadline-secret", raw = JSON.stringify({kind:"project",goal:"owned forwarding",eventId:"owner-1"});
async function fixture(mode: "ok" | "headers" | "body" | "error-body", deadline?: string) {
 const root=mkdtempSync(join(tmpdir(),"keep-forwarding-deadline-")),file=join(root,"replay"),outbox=join(root,"outbox"),sockets=new Set<Socket>(),held=new Set<ServerResponse>(),children:ChildProcess[]=[];
 const sink=createServer(async(req,res)=>{let body="";for await(const chunk of req)body+=chunk;appendFileSync(outbox,JSON.stringify({body})+"\n");
 if(mode==="ok"){res.writeHead(200,{"content-type":"application/json"});res.end('{"status":"accepted"}');}
 else{held.add(res);if(mode!=="headers"){res.writeHead(mode==="error-body"?503:200,{"content-type":"application/json"});res.flushHeaders();res.write('{"status":');}}});
 sink.on("connection",socket=>{sockets.add(socket);socket.on("close",()=>sockets.delete(socket));});sink.listen(0,"127.0.0.1");await once(sink,"listening");const address=sink.address();assert.ok(address&&typeof address==="object");const port=address.port;
 const count=()=>{try{return readFileSync(outbox,"utf8").trim().split("\n").filter(Boolean).length;}catch{return 0;}};
 const state=()=>JSON.parse(readFileSync(`${file}.delivery-v1.json`,"utf8")).rows[0]?.state;
 async function start(){const url=new URL("../src/channel/chat_server.js",import.meta.url).href;
 const script=`const timers=new Map(); const set=globalThis.setTimeout,clear=globalThis.clearTimeout; globalThis.setTimeout=(fn,ms,...args)=>{const owned=(new Error().stack.split("\\n")[2]??"").includes("chat_server.js");let timer;timer=set((...a)=>{timers.delete(timer);fn(...a);},ms,...args);if(owned)timers.set(timer,ms);return timer;};globalThis.clearTimeout=timer=>{timers.delete(timer);return clear(timer);};process.on("message",m=>{if(m.type==="inspect")process.send({timers:[...timers.values()]});}); const adapter=await import(${JSON.stringify(url)});await adapter.main();`;
 const env:NodeJS.ProcessEnv={...process.env,KEEP_GATEWAY_ORIGIN:`http://127.0.0.1:${port}`,KEEP_GATEWAY_TOKEN:"owned-token",KEEP_CHAT_SECRET:SECRET,KEEP_CHAT_REPLAY_FILE:file,KEEP_CHAT_PORT:"0"};delete env["NODE_TEST_CONTEXT"];if(deadline!==undefined)env["KEEP_CHAT_FORWARD_TIMEOUT_MS"]=deadline;else delete env["KEEP_CHAT_FORWARD_TIMEOUT_MS"];
 const child=spawn(process.execPath,["--input-type=module","--eval",script],{env,stdio:["ignore","pipe","pipe","ipc"]});children.push(child);let stdout="",stderr="";child.stderr?.on("data",d=>stderr+=d);
 const origin=await new Promise<string>((resolve,reject)=>{const timer=setTimeout(()=>{child.kill("SIGKILL");reject(new Error("owned startup deadline"));},3000);child.once("error",e=>{clearTimeout(timer);reject(e);});child.once("exit",code=>{clearTimeout(timer);reject(new Error(`adapter exited ${code}: ${stderr}`));});child.stdout?.on("data",d=>{stdout+=d;if(!stdout.includes("\n"))return;clearTimeout(timer);const ready=JSON.parse(stdout.split("\n")[0]!);resolve(`http://${ready.host}:${ready.port}`);});});
 return{origin,child,async inspect():Promise<{timers:number[]}>{const ack=once(child,"message");child.send({type:"inspect"});return(await ack)[0] as {timers:number[]};},async stop(){const closed=once(child,"close");child.kill("SIGTERM");await closed;}};}
 async function send(origin:string,body=raw){const ts=String(Math.floor(Date.now()/1000)),signature=createHmac("sha256",SECRET).update(`${ts}.${body}`).digest("hex");const started=performance.now();try{const res=await fetch(`${origin}/event`,{method:"POST",headers:{"x-webhook-timestamp":ts,"x-webhook-signature":`sha256=${signature}`},body,signal:AbortSignal.timeout(800)});await res.text();return{status:res.status,elapsed:performance.now()-started};}catch{return{status:0,elapsed:performance.now()-started};}}
 async function cleanup(){for(const child of children)if(child.exitCode===null&&child.signalCode===null){const closed=once(child,"close");child.kill("SIGKILL");await closed;}for(const socket of sockets)socket.destroy();await new Promise<void>(resolve=>sink.close(()=>resolve()));rmSync(root,{recursive:true,force:true});}
 return{start,send,count,state,cleanup,sockets,release(){for(const res of held){if(!res.headersSent)res.writeHead(200,{"content-type":"application/json"});res.end('{"status":"accepted"}');}}};
}

test("successful request clears its timer and request socket; a late deadline leaves confirmation intact",{timeout:10000},async()=>{
 const f=await fixture("ok","150");try{const a=await f.start();assert.equal((await f.send(a.origin)).status,200);assert.equal(f.count(),1);assert.equal(f.state(),"confirmed");await new Promise(resolve=>setTimeout(resolve,250));assert.equal((await a.inspect()).timers.length,0);assert.equal(f.sockets.size,0);assert.equal(f.state(),"confirmed");}finally{await f.cleanup();}
});
for(const mode of ["headers","body","error-body"] as const)test(`holding ${mode} is bounded and preserves entered uncertainty`,{timeout:10000},async()=>{
 const f=await fixture(mode,"100");try{let a=await f.start();const result=await f.send(a.origin);assert.equal(result.status,502);assert.ok(result.elapsed>=80&&result.elapsed<600,JSON.stringify(result));assert.equal(f.count(),1);assert.equal(f.state(),"unknown");assert.equal((await a.inspect()).timers.length,0);
 await a.stop();a=await f.start();assert.equal(f.state(),"unknown");assert.equal(f.count(),1);assert.equal((await a.inspect()).timers.length,0);
 }finally{await f.cleanup();}
});
test("invalid deadline refuses before dispatch or journal admission",{timeout:10000},async()=>{
 for(const value of ["0","-1","1.5","NaN","Infinity",String(Number.MAX_SAFE_INTEGER+1),""]){const f=await fixture("ok",value);try{await assert.rejects(f.start(),/positive safe integer/);assert.equal(f.count(),0);}finally{await f.cleanup();}}
});
test("large admitted deadline avoids timer overflow and default remains finite",{timeout:10000},async()=>{
 for(const value of [undefined,"1000000000000"]){const f=await fixture("headers",value);try{const a=await f.start(),pending=f.send(a.origin);while(f.count()===0)await new Promise(resolve=>setTimeout(resolve,1));const timers=(await a.inspect()).timers;assert.equal(timers.length,1);assert.ok(timers[0]!>1000&&timers[0]!<=2147483647);if(value===undefined)assert.ok(timers[0]!<=10000);f.release();assert.equal((await pending).status,200);assert.equal((await a.inspect()).timers.length,0);}finally{await f.cleanup();}}
});
