import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { CodexProjectProvider, authorizeCodexFollowup, codexProjectIdentity, inspectCodexInvocations, type CodexProjectDescriptor } from "../src/gateway/codex_project_provider.js";
import { runCodexUsageCommand } from "../src/cli/codex_usage.js";
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
 if(${JSON.stringify(mode)}==='fail'){console.error('PRIVATE-TEST-SECRET');console.log('bad-json');return;}
 const events=[{type:'thread.started',thread_id:'fixture'}];
 if(${JSON.stringify(mode)}.startsWith('warning'))events.push({type:'item.completed',item:{type:'error',message:'Code Mode is unavailable because failed to spawn code-mode host /PRIVATE-TEST-SECRET/codex-code-mode-host: host executable was not found. Code mode will fail closed; enable '+String.fromCharCode(96)+'features.code_mode_host'+String.fromCharCode(96)+' and install '+String.fromCharCode(96)+'codex-code-mode-host'+String.fromCharCode(96)+'.'}});
 if(${JSON.stringify(mode)}!=='warning-incomplete')events.push({type:'turn.started'},{type:'item.completed',item:{id:'1',type:'agent_message',text:JSON.stringify({text:'proposal'})}},{type:'turn.completed',usage:{input_tokens:10,cached_input_tokens:2,output_tokens:5}});
 for(const x of events)console.log(JSON.stringify(x));
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
  const failed=f.spine().currentEvents().at(-1);assert.equal(failed?.payload['event'],'uncertain');assert.ok(failed?.payload['diagnostics']);assert.equal(JSON.stringify(failed).includes('PRIVATE-TEST-SECRET'),false);
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

function priorUncertainty(f: ReturnType<typeof fixture>, pending = false) {
 const spine=f.spine(),id=randomUUID();
 spine.stage({type:'identity.action',actor:'codex.project-generation',payload:{event:'claimed',id,binding:'historical-profile'}});
 if(!pending)spine.stage({type:'identity.action',actor:'codex.project-generation',payload:{event:'uncertain',id,binding:'historical-profile'}});
 return id;
}

test('Codex warning codes survive completed and uncertain provider outcomes without raw diagnostics',async()=>{
 for(const mode of ['warning','warning-incomplete']){
  const f=fixture(mode);try{
   const p=new CodexProjectProvider(f.descriptor,f.spine());
   if(mode==='warning')assert.equal((await p.generate(generationRequest(p,{prompt:'p'}))).text,'proposal');
   else await assert.rejects(p.generate(generationRequest(p,{prompt:'p'})));
   const outcome=f.spine().currentEvents().at(-1)!;
   assert.equal(outcome.payload['event'],mode==='warning'?'completed':'uncertain');
   const warningOwner=mode==='warning'?outcome.payload:outcome.payload['diagnostics'] as Record<string,unknown>;
   assert.deepEqual(warningOwner['warnings'],['code-mode-host-unavailable']);
   assert.equal(JSON.stringify(outcome).includes('PRIVATE-TEST-SECRET'),false);
  }finally{rmSync(f.root,{recursive:true,force:true});}
 }
});

for (const profile of ['keep.codex-generation/v2','keep.codex-generation/v3'])
test(`current native profile cannot inherit an owner follow-up authorization for ${profile}`,async()=>{
 const f=fixture('success',2);try{
  const id=priorUncertainty(f),spine=f.spine();
  const oldBinding=createHash('sha256').update(JSON.stringify({profile,descriptor:Object.fromEntries(Object.entries(f.descriptor).sort(([a],[b])=>a.localeCompare(b)))})).digest('hex');
  assert.notEqual(codexProjectIdentity(f.descriptor),oldBinding);
  spine.stage({type:'identity.action',actor:'codex.project-generation',payload:{event:'followup-authorized',binding:oldBinding,uncertainClaimIds:[id],expectedClaims:1,additionalInvocations:1}});
  const p=new CodexProjectProvider(f.descriptor,spine);
  await assert.rejects(p.generate(generationRequest(p,{prompt:'p'})),/prior work is uncertain/);
  assert.equal(existsSync(f.record),false);
  assert.equal((await inspectCodexInvocations(spine)).claimed,1);
 }finally{rmSync(f.root,{recursive:true,force:true});}
});
test('owner follow-up survives restart, retains uncertainty and spends only its exact finite allowance',async()=>{
 const f=fixture('success',3);try{
  const id=priorUncertainty(f), review={uncertainClaimIds:[id],expectedClaims:1,additionalInvocations:2};
  const original=f.spine().currentEvents();
  await authorizeCodexFollowup(f.spine(),f.descriptor,review);
  const eventCount=f.spine().currentEvents().length;
  await authorizeCodexFollowup(f.spine(),f.descriptor,review);
  assert.equal(f.spine().currentEvents().length,eventCount,'repeated acknowledgement is idempotent');
  await f.spine().seal();
  const p=new CodexProjectProvider(f.descriptor,f.spine());
  assert.equal((await p.generate(generationRequest(p,{prompt:'first'}))).text,'proposal');
  const restarted=new CodexProjectProvider(f.descriptor,f.spine());
  assert.equal((await restarted.generate(generationRequest(restarted,{prompt:'second'}))).text,'proposal');
  await assert.rejects(restarted.generate(generationRequest(restarted,{prompt:'third'})),/follow-up invocation allowance exhausted/);
  const state=await inspectCodexInvocations(f.spine());
  assert.equal(state.claimed,3);assert.deepEqual(state.unresolved,[{id,binding:'historical-profile',state:'uncertain'}]);
  assert.deepEqual(f.spine().currentEvents().slice(0,original.length),original,'old evidence is unchanged');
 }finally{rmSync(f.root,{recursive:true,force:true});}
});
test('owner review refuses unauthorized, stale, pending or incomplete claims and cannot transfer to a changed binding',async()=>{
 const f=fixture('success',4);try{
  const id=priorUncertainty(f), args=['authorize-followup',`--uncertain=${id}`,'--expected-claims=1','--additional-invocations=2'];
  const output:string[]=[];
  assert.equal(await runCodexUsageCommand(f.spine(),args,false,f.descriptor,s=>output.push(s)),2);
  assert.match(output.join('\n'),/local personal owner/);
  assert.equal((await inspectCodexInvocations(f.spine())).followupAuthorizations.length,0);
  await assert.rejects(authorizeCodexFollowup(f.spine(),f.descriptor,{uncertainClaimIds:[id],expectedClaims:2,additionalInvocations:1}),/claims changed/);
  const pending=priorUncertainty(f,true);
  await assert.rejects(authorizeCodexFollowup(f.spine(),f.descriptor,{uncertainClaimIds:[id],expectedClaims:2,additionalInvocations:1}),/claims changed/);
  await assert.rejects(authorizeCodexFollowup(f.spine(),f.descriptor,{uncertainClaimIds:[id,pending],expectedClaims:2,additionalInvocations:1}),/pending Codex invocation/);
  f.spine().stage({type:'identity.action',actor:'codex.project-generation',payload:{event:'uncertain',id:pending,binding:'historical-profile'}});
  assert.equal(await runCodexUsageCommand(f.spine(),['authorize-followup',`--uncertain=${id},${pending}`,'--expected-claims=2','--additional-invocations=1'],true,f.descriptor,s=>output.push(s)),0);
  assert.equal(existsSync(f.record),false,'administration never invokes the model');
  const changed=new CodexProjectProvider({...f.descriptor,model:'changed'},f.spine());
  await assert.rejects(changed.generate(generationRequest(changed,{prompt:'p'})),/prior work is uncertain/);
  assert.notEqual(codexProjectIdentity({...f.descriptor,maxInvocations:5}),codexProjectIdentity(f.descriptor));
 }finally{rmSync(f.root,{recursive:true,force:true});}
});
test('a newly uncertain follow-up blocks remaining approved calls until that exact new claim is reviewed',async()=>{
 const f=fixture('fail',3);try{
  const id=priorUncertainty(f);
  await authorizeCodexFollowup(f.spine(),f.descriptor,{uncertainClaimIds:[id],expectedClaims:1,additionalInvocations:2});
  const p=new CodexProjectProvider(f.descriptor,f.spine());
  await assert.rejects(p.generate(generationRequest(p,{prompt:'p'})));
  const state=await inspectCodexInvocations(f.spine());assert.equal(state.claimed,2);assert.equal(state.unresolved.length,2);
  await assert.rejects(new CodexProjectProvider(f.descriptor,f.spine()).generate(generationRequest(p,{prompt:'p'})),/prior work is uncertain/);
  await assert.rejects(authorizeCodexFollowup(f.spine(),f.descriptor,{uncertainClaimIds:[id],expectedClaims:2,additionalInvocations:1}),/claims changed/);
 }finally{rmSync(f.root,{recursive:true,force:true});}
});
test('installed usage inspection needs only existing owner state, refuses remote or wrong authority and never invokes Codex',()=>{
 const f=fixture();try{
  priorUncertainty(f);writeFileSync(join(f.root,'data','owner-token'),'a'.repeat(64)+'\n',{mode:0o600});
  const inherited=Object.fromEntries(Object.entries(process.env).filter(([name])=>!name.startsWith('KEEP_')));
  const run=(extra:Record<string,string>)=>spawnSync(process.execPath,[join(process.cwd(),'dist/src/main.js'),'codex-usage','status'],{
   cwd:f.root,env:{...inherited,KEEP_DATA_DIR:join(f.root,'data'),...extra},encoding:'utf8',timeout:10000});
  const ok=run({});assert.equal(ok.status,0,ok.stderr);assert.equal(JSON.parse(ok.stdout).claimed,1);
  for(const extra of [{KEEP_OWNER_TOKEN:'wrong'}, {KEEP_GATEWAY_URL:'http://127.0.0.1:1'}]){
   const refused=run(extra);assert.equal(refused.status,2,refused.stdout+refused.stderr);assert.match(refused.stdout+refused.stderr,/local personal owner|local owner operation/);
  }
  assert.equal(existsSync(f.record),false);
 }finally{rmSync(f.root,{recursive:true,force:true});}
});
