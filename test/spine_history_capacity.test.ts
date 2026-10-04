import {test} from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {createHash} from "node:crypto";
import {syncBuiltinESMExports} from "node:module";
import {FileSpineStore} from "../src/spine/store.js";
import {sealBlock} from "../src/spine/hashchain.js";
import type {StagedEvent} from "../src/spine/event.js";
const event=(id:string,data="é"):StagedEvent=>({id,schemaVersion:1,type:"generic",actor:id.startsWith("org")?"tenant-a-agent":"owner",ts:1234,payload:{data}});
const line=(row:StagedEvent)=>JSON.stringify(row)+"\n";
const capacity=(error:unknown)=>!!error&&typeof error==="object"&&(error as {code?:string}).code==="KEEP_SPINE_HISTORY_CAPACITY";
function fixture(maxHistoryBytes:number){const dir=fs.mkdtempSync(join(tmpdir(),"keep-spine-capacity-")),opts={fsync:true,maxHistoryBytes},store=new FileSpineStore(dir,opts);return{dir,store,log:join(dir,"staging.jsonl"),cursor:join(dir,"staging.cursor"),cleanup(){fs.rmSync(dir,{recursive:true,force:true});}};}
test("exact-byte history admits scoped events and duplicates without silent growth",()=>{
 const a=event("owner"),b=event("org-a"),max=Buffer.byteLength(line(a)+line(b)),f=fixture(max);try{f.store.appendStaged(a);f.store.appendStaged(b);const before=fs.readFileSync(f.log);assert.equal(before.length,max);f.store.appendStaged(a);assert.deepEqual(fs.readFileSync(f.log),before);assert.deepEqual(f.store.readStaged().map(e=>e.id),["owner","org-a"]);f.store.removeStaged(1);assert.deepEqual(f.store.readStaged().map(e=>e.id),["org-a"]);assert.equal(fs.readFileSync(f.cursor,"utf8"),"1\n");assert.throws(()=>f.store.appendStaged(event("extra")),capacity);assert.deepEqual(fs.readFileSync(f.log),before);assert.equal(fs.readFileSync(f.cursor,"utf8"),"1\n");}finally{f.cleanup();}
});
test("oversized existing history and multibyte append refuse preserving carriers",()=>{
 const f=fixture(128);try{const cursor=fs.readFileSync(f.cursor);fs.writeFileSync(f.log," ".repeat(129));const before=fs.readFileSync(f.log);assert.throws(()=>f.store.readStaged(),capacity);assert.throws(()=>f.store.appendStaged(event("no-entry")),capacity);assert.throws(()=>f.store.removeStaged(0),capacity);assert.deepEqual(fs.readFileSync(f.log),before);assert.deepEqual(fs.readFileSync(f.cursor),cursor);fs.writeFileSync(f.log,"");assert.throws(()=>f.store.appendStaged(event("org-multibyte","界".repeat(50))),capacity);assert.equal(fs.readFileSync(f.log).length,0);}finally{f.cleanup();}
});
test("newline recovery and prospective append are preflighted before any tail changes",()=>{
 const row=event("owner"),tail=JSON.stringify(row),f=fixture(Buffer.byteLength(tail));try{fs.writeFileSync(f.log,tail);const before=fs.readFileSync(f.log),cursor=fs.readFileSync(f.cursor);assert.throws(()=>f.store.appendStaged(row),capacity);assert.throws(()=>f.store.prepareForSeal(),capacity);assert.deepEqual(fs.readFileSync(f.log),before);assert.deepEqual(fs.readFileSync(f.cursor),cursor);
 fs.writeFileSync(f.log,'{"id":"torn');const torn=fs.readFileSync(f.log);assert.throws(()=>f.store.appendStaged(event("too-large","x".repeat(1000))),capacity);assert.deepEqual(fs.readFileSync(f.log),torn);assert.equal(fs.readdirSync(f.dir).some(p=>p.includes(".torn-")),false);
 }finally{f.cleanup();}
});


test("descriptor growth is observed within cap plus one byte and preserves grown state",()=>{
 const f=fixture(128),open=fs.openSync,stat=fs.fstatSync,read=fs.readSync,paths=new Map<number,string>();let grown=false,observed=0;fs.writeFileSync(f.log," ");let retained:Buffer|undefined;
 try {
 fs.openSync=((p:fs.PathLike,flags:fs.OpenMode,...rest:unknown[])=>{const fd=(open as Function)(p,flags,...rest) as number;paths.set(fd,String(p));return fd;}) as typeof fs.openSync;
 fs.fstatSync=((fd:number,...rest:unknown[])=>{const value=(stat as Function)(fd,...rest);if(paths.get(fd)===f.log&&!grown){grown=true;fs.appendFileSync(f.log," ".repeat(200));retained=Buffer.from(" ".repeat(201));}return value;}) as typeof fs.fstatSync;
 fs.readSync=((fd:number,...rest:unknown[])=>{const n=(read as Function)(fd,...rest) as number;if(paths.get(fd)===f.log)observed+=n;return n;}) as typeof fs.readSync;syncBuiltinESMExports();
 assert.throws(()=>f.store.readStaged(),capacity);assert.ok(grown);assert.ok(observed>0&&observed<=129);assert.deepEqual(fs.readFileSync(f.log),retained);assert.equal(fs.readFileSync(f.cursor,"utf8"),"0\n");
 }finally{fs.openSync=open;fs.fstatSync=stat;fs.readSync=read;syncBuiltinESMExports();f.cleanup();}
});

test("oversized cursor and recovery comparison carriers refuse without truncation",()=>{
 const f=fixture(512);try{fs.writeFileSync(f.cursor,"1".repeat(33));const cursor=fs.readFileSync(f.cursor);assert.throws(()=>f.store.readStaged(),capacity);assert.deepEqual(fs.readFileSync(f.cursor),cursor);
 fs.writeFileSync(f.cursor,"0\n");const torn=Buffer.from('{"id":"torn'),saved=`${f.log}.torn-0-${createHash("sha256").update(torn).digest("hex")}`;fs.writeFileSync(f.log,torn);fs.writeFileSync(saved,"x".repeat(513));const sidecar=fs.readFileSync(saved);assert.throws(()=>f.store.appendStaged(event("owner")),capacity);assert.deepEqual(fs.readFileSync(f.log),torn);assert.deepEqual(fs.readFileSync(saved),sidecar);assert.equal(fs.readFileSync(f.cursor,"utf8"),"0\n");
 }finally{f.cleanup();}
});

test("invalid history capacity refuses before creating store files",()=>{
 const root=fs.mkdtempSync(join(tmpdir(),"keep-spine-config-"));try{for(const maxHistoryBytes of [0,-1,NaN,Infinity,1.5,Number.MAX_SAFE_INTEGER+1]){const dir=join(root,String(maxHistoryBytes));assert.throws(()=>new FileSpineStore(dir,{maxHistoryBytes}),/positive finite safe/);assert.equal(fs.existsSync(dir),false);}}finally{fs.rmSync(root,{recursive:true,force:true});}
});

test("proposed default64MiB read has measured memory/time on owned valid history",{timeout:30000},()=>{
 const cap=64*1024*1024,f=fixture(cap);try{let size=0;for(let i=0;i<64;i++){const row=line(event(`owner-${i}`,"x".repeat(1024*1024-1024)));fs.appendFileSync(f.log,row);size+=Buffer.byteLength(row);}fs.appendFileSync(f.log,Buffer.alloc(cap-size-1,32));fs.appendFileSync(f.log,"\n");
 const before=process.memoryUsage().rss,started=performance.now();const rows=new FileSpineStore(f.dir,{fsync:true}).readStaged();const elapsedMs=performance.now()-started;assert.equal(rows.length,64);assert.equal(fs.statSync(f.log).size,cap);console.log(JSON.stringify({case:"T015-default-observation",historyBytes:cap,rows:rows.length,elapsedMs,rssBefore:before,rssAfter:process.memoryUsage().rss,maxRssKiB:process.resourceUsage().maxRSS,limitMiB:1536}));
 fs.appendFileSync(f.log," ");assert.throws(()=>new FileSpineStore(f.dir).readStaged(),capacity);assert.equal(fs.statSync(f.log).size,cap+1);assert.equal(new FileSpineStore(f.dir,{maxHistoryBytes:cap+1}).readStaged().length,64);
 }finally{f.cleanup();}
});


test("chain admission and newline recovery preserve exact-boundary history",()=>{
 const first=sealBlock(undefined,[event("owner")],1234),raw=JSON.stringify(first)+"\n",f=fixture(Buffer.byteLength(raw)),chain=join(f.dir,"chain.jsonl");
 try{f.store.appendBlock(first);const before=fs.readFileSync(chain);f.store.appendBlock(first);assert.deepEqual(fs.readFileSync(chain),before);assert.equal(f.store.lastBlock()!.hash,first.hash);
 assert.throws(()=>f.store.appendBlock(sealBlock(first,[event("org-a")],1235)),capacity);assert.deepEqual(fs.readFileSync(chain),before);assert.equal(fs.readFileSync(f.cursor,"utf8"),"0\n");
 fs.writeFileSync(chain,before.subarray(0,-1));f.store.appendBlock(first);assert.deepEqual(fs.readFileSync(chain),before);
 const fullTail=JSON.stringify(sealBlock(undefined,[event("owner","x".repeat(128))],1234));const tiny=new FileSpineStore(f.dir,{maxHistoryBytes:Buffer.byteLength(fullTail)});fs.writeFileSync(chain,fullTail);assert.throws(()=>tiny.prepareForSeal(),capacity);assert.equal(fs.readFileSync(chain,"utf8"),fullTail);
 }finally{f.cleanup();}
});
