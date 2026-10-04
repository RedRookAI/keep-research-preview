#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { spawnSync, execFileSync } from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { FileSpineStore } from '../dist/src/spine/store.js';
import { Spine } from '../dist/src/spine/spine.js';
import { InProcessLock } from '../dist/src/lock/lock.js';
import { SchemaRegistry } from '../dist/src/spine/upcaster.js';
const root = resolve(fileURLToPath(new URL('../', import.meta.url)));
const script = fileURLToPath(import.meta.url), hash = bytes => createHash('sha256').update(bytes).digest('hex');
const files = ['spine/store','spine/event','spine/hashchain','spine/spine','spine/durable_fs','spine/logical_append_lock','lock/lock','spine/upcaster'].flatMap(p=>[`src/${p}.ts`,`dist/src/${p}.js`]);
const sourceIdentity = () => Object.fromEntries([...files,'tools/measure_spine_history.mjs'].map(p=>[p,hash(fs.readFileSync(join(root,p)))]));
const event = n => ({id:`event-${String(n).padStart(8,'0')}`,schemaVersion:1,type:'generic',actor:n%2?'tenant-alpha':'owner-source',ts:1234,payload:{data:'x'.repeat(1024)}});
function measure(rows, fsync) {
 const dir=fs.mkdtempSync(join(tmpdir(),'keep-spine-measure-')),path=join(dir,'staging.jsonl');let result;
 try {
  const store=new FileSpineStore(dir,{fsync}),encoded=JSON.stringify(event(0))+'\n',eventBytes=Buffer.byteLength(encoded);
  for(let i=0;i<rows;i++){const line=JSON.stringify(event(i))+'\n';assert.equal(Buffer.byteLength(line),eventBytes);fs.appendFileSync(path,line);}
  const initialHash=hash(fs.readFileSync(path)),initialBytes=fs.statSync(path).size;
  const open=fs.openSync,close=fs.closeSync,read=fs.readSync,paths=new Map();let readBytes=0,readCalls=0;
  const before=process.memoryUsage().rss,started=performance.now();
  try {
   fs.openSync=(p,flags,...args)=>{const fd=open(p,flags,...args);paths.set(fd,String(p));return fd;};
   fs.closeSync=fd=>{paths.delete(fd);return close(fd);};
   fs.readSync=(fd,...args)=>{const n=read(fd,...args);if(paths.get(fd)===path){readBytes+=n;readCalls++;}return n;};syncBuiltinESMExports();
   for(let i=0;i<20;i++)store.appendStaged(event(rows+i));
  }finally{fs.openSync=open;fs.closeSync=close;fs.readSync=read;syncBuiltinESMExports();}
  const elapsedMs=performance.now()-started,rssAfter=process.memoryUsage().rss;
  assert.equal(readBytes,eventBytes*(20*rows+190));
  const after=fs.readFileSync(path);assert.equal(after.length,initialBytes+20*eventBytes);assert.equal(hash(after.subarray(0,initialBytes)),initialHash);
  store.appendStaged(event(0));assert.deepEqual(fs.readFileSync(path),after);assert.throws(()=>store.appendStaged({...event(0),actor:'changed'}),/different content/);
  const restarted=new FileSpineStore(dir,{fsync});assert.equal(restarted.readStaged().length,rows+20);
  result={rows,fsync,appends:20,eventBytes,payloadBytes:1024,initialBytes,initialSha256:initialHash,finalSha256:hash(after),elapsedMs,elapsedMsPerAppend:elapsedMs/20,rssBefore:before,rssAfter,maxRssKiB:process.resourceUsage().maxRSS,stagingDescriptorReadBytes:readBytes,stagingDescriptorReadCalls:readCalls,actualDuplicateRefused:true,actualChangedDuplicateRefused:true,actualRestartRows:rows+20};
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
 assert.equal(fs.existsSync(dir),false);return {...result,cleanup:{ownedRoot:dir,removed:true}};
}
async function integration(fsync) {
 const dir=fs.mkdtempSync(join(tmpdir(),'keep-spine-measure-seal-'));let result;
 try {
  const a=new FileSpineStore(dir,{fsync}),b=new FileSpineStore(dir,{fsync}),spine=new Spine(a,new InProcessLock(),new SchemaRegistry(),()=>1234);
  a.appendStaged(event(1));await spine.seal();b.appendStaged(event(2));a.appendStaged(event(1));assert.equal(a.readStaged().length,1);assert.equal(a.readStaged()[0].id,event(2).id);await spine.seal();
  const restored=new Spine(new FileSpineStore(dir,{fsync}),new InProcessLock(),new SchemaRegistry(),()=>1234);
  assert.equal(restored.verify().ok,true);assert.deepEqual(restored.replay().map(e=>e.id),[event(1).id,event(2).id]);assert.equal(restored.pending().length,0);assert.equal(fs.readFileSync(join(dir,'staging.cursor'),'utf8'),'2\n');
  result={fsync,actualTwoInstanceInterleavedAppendSeal:true,actualRestartVerified:true,retainedConsumedDuplicateSuppressed:true,cursor:'2',events:[event(1).id,event(2).id]};
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
 assert.equal(fs.existsSync(dir),false);return {...result,cleanup:{ownedRoot:dir,removed:true}};
}
function counterexamples() {
 // Small executable state models are falsifiers, not optimized filesystem stores.
 const scenarios=['duplicate','restart','interleaved-append-seal'];
 const run=(alternative,scenario,repair)=>{
  let retained=['owner-1'],cache=new Set(retained),consumed=0;
  if(scenario==='restart')cache=new Set();
  if(scenario==='interleaved-append-seal'){consumed=1;retained.push('tenant-a-1');}
  const id=scenario==='interleaved-append-seal'?'tenant-a-1':'owner-1';
  if(alternative==='segments'&&!repair)retained=retained.slice(consumed||1);
  const seen=repair?new Set(retained):alternative==='index'?cache:new Set(retained);
  return {scenario,duplicateWouldBeAdmitted:!seen.has(id)};
 };
 return ['index','segments'].map(alternative=>{const naive=scenarios.map(s=>run(alternative,s,false)),retentionRepairModel=scenarios.map(s=>run(alternative,s,true));assert.ok(naive.some(r=>r.duplicateWouldBeAdmitted));assert.ok(retentionRepairModel.every(r=>!r.duplicateWouldBeAdmitted));return {alternative,evidenceKind:'EXECUTABLE_IN_MEMORY_COUNTEREXAMPLE_ONLY',naive,retentionRepairModel,productionAlternativeImplemented:false,crashSafetyQualified:false};});
}
if(process.argv.length!==2)throw new Error('No arguments accepted; workload matrix is fixed');
if(process.version!=='v22.23.2')throw new Error('Node22.23.2 required');
const worker=process.env.KEEP_SPINE_MEASURE_CASE;
if(worker!==undefined){const {rows,fsync}=JSON.parse(worker);if(![100,1000,10000].includes(rows)||typeof fsync!=='boolean')throw new Error('Invalid fixed workload');process.stdout.write(JSON.stringify(measure(rows,fsync))+'\n');}
else {
 const started=performance.now(),before=sourceIdentity(),matrix=[],deadline=performance.now()+120000;
 const sourceHead=execFileSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8',timeout:2000}).trim();
 for(const rows of [100,1000,10000])for(const fsync of [false,true]){const remaining=deadline-performance.now();if(remaining<=0)throw new Error('Finite matrix deadline exhausted');const env={...process.env,KEEP_SPINE_MEASURE_CASE:JSON.stringify({rows,fsync})};delete env.NODE_TEST_CONTEXT;const child=spawnSync(process.execPath,[script],{cwd:root,env,encoding:'utf8',timeout:Math.min(60000,remaining),maxBuffer:1024*1024});if(child.status!==0)throw new Error(`Measurement child failed ${child.status}: ${child.stderr}`);matrix.push(JSON.parse(child.stdout));}
 const consumerCases=[];for(const fsync of [false,true])consumerCases.push(await integration(fsync));
 const models=counterexamples(),after=sourceIdentity();assert.deepEqual(after,before);
 const report={schema:'keep.spine-staging-measurement/v1',measuredAt:new Date().toISOString(),sourceHead,inputSha256:before,node:process.version,platform:process.platform,result:'MEASUREMENT_COMPLETE',runtimeOptimizationImplemented:false,productionThroughputQualified:false,deadlineMs:120000,elapsedMs:performance.now()-started,matrix,consumerCases,alternativeCounterexamples:models,limitations:['Synthetic fixed1KiB payload and warm local page-cache workload; bootstrap fixture writes excluded from20 admitted appends.','RSS includes runtime and fixture preparation; per-child maxRSS is not parsed-heap or production SLA.','Read-byte counter covers actual staging descriptor reads during20 appends, excluding cursor/lock metadata and later correctness probes.','Index/segment alternatives are explicit counterexample/repair models, not implemented stores or physical power-cut qualification.','Existing coherent local filesystem/process identity and sealer ownership are required.'],cleanupVerified:matrix.every(r=>r.cleanup.removed)&&consumerCases.every(r=>r.cleanup.removed)};
 fs.writeFileSync(join(root,'docs/qualification/spine-history-measurement.json'),JSON.stringify(report,null,2)+'\n');process.stdout.write(JSON.stringify(report)+'\n');
}
