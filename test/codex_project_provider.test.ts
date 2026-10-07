import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { CodexProjectProvider, type CodexProjectDescriptor } from "../src/gateway/codex_project_provider.js";
import { generationRequest } from "../src/gateway/gateway.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
function fixture(mode="success",maxInvocations=1) {
 const root=mkdtempSync(join(tmpdir(),"keep-codex-admission-")), executable=join(root,"codex"), record=join(root,"entered");
 writeFileSync(executable,`#!${process.execPath}
const fs=require('node:fs');process.stdin.resume();process.stdin.on('end',()=>{
 fs.writeFileSync(${JSON.stringify(record)},'entered');
 if(${JSON.stringify(mode)}==='fail'){console.log('bad-json');return;}
 for(const x of [{type:'thread.started',thread_id:'fixture'},{type:'turn.started'},{type:'item.completed',item:{id:'1',type:'agent_message',text:JSON.stringify({text:'proposal'})}},{type:'turn.completed',usage:{input_tokens:10,cached_input_tokens:2,output_tokens:5}}])console.log(JSON.stringify(x));
});`,{mode:0o700});
 const descriptor:CodexProjectDescriptor={executable,executableSha256:createHash('sha256').update(readFileSync(executable)).digest('hex'),cliVersion:'codex-cli 0.159.3',model:'fixture',maxSubmittedPromptBytes:4096,maxCapturedOutputBytes:4096,maxElapsedMs:2000,maxInvocations,processing:'owner-public-repository'};
 const spine=()=>new Spine(new FileSpineStore(join(root,'data'),{fsync:true}),new InProcessLock(),new SchemaRegistry());
 return {root,record,executable,descriptor,spine};
}
test('Codex completed invocations remain charged across restart before and after sealing',async()=>{
 const f=fixture();try{
  const spine=f.spine(),p=new CodexProjectProvider(f.descriptor,spine);
  const api={prompt:'p',maxTokens:10};assert.equal(generationRequest({ ...p, generationMode:undefined } as never,api),api);
  assert.equal(p.isLocal,false);
  const response=await p.generate(generationRequest(p,api));assert.equal(response.text,'proposal');
  for(const seal of [false,true]){
   if(seal)await spine.seal();
   await assert.rejects(new CodexProjectProvider({...f.descriptor,model:'different-model'},f.spine()).generate(generationRequest(p,api)),/allowance exhausted/);
  }
 }finally{rmSync(f.root,{recursive:true,force:true});}
});
test('entered failure and a pending claim prevent restart dispatch',async()=>{
 const f=fixture('fail',3);try{
  const p=new CodexProjectProvider(f.descriptor,f.spine());
  await assert.rejects(p.generate(generationRequest(p,{prompt:'p'})));
  await assert.rejects(new CodexProjectProvider(f.descriptor,f.spine()).generate(generationRequest(p,{prompt:'p'})),/prior work is uncertain/);
 }finally{rmSync(f.root,{recursive:true,force:true});}
});
test('authority and executable drift refuse before generation',async()=>{
 const f=fixture();try{
  const p=new CodexProjectProvider(f.descriptor,f.spine());
  await assert.rejects(p.generate(generationRequest(p,{prompt:'p',assertAuthority:()=>{throw Error('stale approval');}})),/stale approval/);
  writeFileSync(f.executable,'changed');
  await assert.rejects(p.generate(generationRequest(p,{prompt:'p'})),/identity changed/);
  assert.equal(existsSync(f.record),false);
 }finally{rmSync(f.root,{recursive:true,force:true});}
});
test('a known pre-dispatch refusal remains not-started rather than uncertain remote work',async()=>{
 const f=fixture('success',2);try{
  const spine=f.spine(),p=new CodexProjectProvider(f.descriptor,spine);
  await assert.rejects(p.generate(generationRequest(p,{prompt:'x'.repeat(4096)})));
  assert.equal(existsSync(f.record),false);
  assert.equal(spine.currentEvents().at(-1)?.payload['event'],'not-started');
  assert.equal((await p.generate(generationRequest(p,{prompt:'p'}))).text,'proposal');
 }finally{rmSync(f.root,{recursive:true,force:true});}
});
