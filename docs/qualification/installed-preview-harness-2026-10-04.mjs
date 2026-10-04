import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync,mkdirSync,readdirSync,lstatSync,existsSync,linkSync} from 'node:fs';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import {createServer} from 'node:net';
const [archive,receiptPath,home]=process.argv.slice(2);
assert.equal(process.argv.length,5);assert.notEqual(process.getuid(),0);
assert.equal(existsSync('/root/keep-release-source'),false);
assert.equal(existsSync('/root/.keep-build/rustup'),false);
const receipt=JSON.parse(readFileSync(receiptPath,'utf8'));
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
assert.equal(receipt.status,'BUILT_FROM_QUALIFIED_SOURCE');
assert.equal(sha(readFileSync(archive)),receipt.archive_sha256);
const env={PATH:'/usr/bin:/bin',HOME:home,TMPDIR:'/tmp',LANG:'C',LC_ALL:'C',
 npm_config_cache:join(home,'empty-cache'),npm_config_offline:'true',npm_config_audit:'false',npm_config_fund:'false',
 npm_config_ignore_scripts:'false',npm_config_userconfig:'/dev/null',GIT_CONFIG_GLOBAL:'/dev/null',GIT_CONFIG_NOSYSTEM:'1'};
function run(label,command,args,cwd=home){
 const result=spawnSync(command,args,{cwd,env,encoding:'utf8',timeout:240000,maxBuffer:8*1024*1024});
 writeFileSync(join(home,label+'.log'),(result.stdout??'')+'\n'+(result.stderr??''),{mode:0o600});
 assert.equal(result.error,undefined,label);assert.equal(result.status,0,label+': '+result.stderr);return result;
}
const prefix=join(home,'prefix2');
run('ordinary-offline-install','npm',['install','--prefix',prefix,'--install-strategy=nested','--offline','--omit=dev','--no-audit','--no-fund',archive]);
const installed=join(prefix,'node_modules/keep');
const pkg=JSON.parse(readFileSync(join(installed,'package.json'),'utf8'));assert.equal(pkg.version,'0.0.5-preview.1');
const actual={};
function walk(root,rel=''){
 for(const name of readdirSync(root).sort()){
  const key=rel?rel+'/'+name:name,p=join(root,name),s=lstatSync(p);
  assert.equal(s.isSymbolicLink(),false,key);
  if(s.isDirectory())walk(p,key);else{assert.equal(s.isFile(),true,key);actual[key]=sha(readFileSync(p));}
 }
}
walk(join(installed,'dist'));assert.deepEqual(actual,Object.fromEntries(Object.entries(receipt.tested_dist_sha256).filter(([path])=>path.startsWith('src/')||path.startsWith('native/'))));
assert.equal(run('cli-version',join(prefix,'node_modules/.bin/keep'),['--version']).stdout.trim(),'keep 0.0.5-preview.1');
assert.match(run('cli-help',join(prefix,'node_modules/.bin/keep'),['--help']).stdout,/keep/i);
writeFileSync(join(prefix,'smoke.mjs'),"import assert from 'node:assert/strict';import * as root from 'keep';import * as core from 'keep/client-core';import * as shell from 'keep/client-shell';assert.equal(typeof root.composeKeep,'function');assert.ok(Object.keys(core).length);assert.deepEqual(Object.keys(core),Object.keys(shell));console.log('exports resolved');\n",{mode:0o600});
run('package-exports',process.execPath,[join(prefix,'smoke.mjs')],prefix);
const recovery=run('installed-accounting',process.execPath,[join(installed,'acceptance/installed_sg32_resources.mjs'),installed,archive,receipt.archive_sha256]);
const recoveryResult=JSON.parse(recovery.stdout.trim());assert.equal(recoveryResult.status,'INSTALLED_UNCERTAIN_CAPACITY_REGRESSION_PASS');
const {ProcessIsolationAdapter}=await import(pathToFileURL(join(installed,'dist/src/infra/process_isolation.js')));
const roots=join(home,'jail-roots');mkdirSync(roots,{mode:0o700});
const project=join(roots,'project'),outside=join(roots,'outside'),input=join(roots,'input');
for(const path of [project,outside,input])mkdirSync(path,{mode:0o700});
const untouched=join(outside,'marker');writeFileSync(untouched,'unchanged');writeFileSync(join(input,'value'),'42');
const adapter=new ProcessIsolationAdapter(), policy={cwd:project,timeoutMs:10000,namespaceJail:{mode:'required',projectDir:project,readOnlyPaths:[input]}};
const code=`const fs=require('node:fs'),a=require('node:assert/strict');fs.writeFileSync(${JSON.stringify(join(project,'useful'))},'42');a.equal(fs.readFileSync(${JSON.stringify(join(input,'value'))},'utf8'),'42');a.throws(()=>fs.writeFileSync(${JSON.stringify(untouched)},'wrong'));a.throws(()=>fs.writeFileSync(${JSON.stringify(join(input,'value'))},'wrong'));a.equal(fs.existsSync('/root'),false);console.log('useful');`;
const useful=await adapter.run('/usr/bin/node',['-e',code],policy);
assert.equal(useful.code,0,JSON.stringify(useful));assert.equal(useful.processIsolation.namespaceSetup,'launcher-confirmed');
assert.equal(readFileSync(join(project,'useful'),'utf8'),'42');assert.equal(readFileSync(untouched,'utf8'),'unchanged');assert.equal(readFileSync(join(input,'value'),'utf8'),'42');
const alias=join(project,'shared');linkSync(untouched,alias);
const refused=await adapter.run('/usr/bin/node',['-e',`require('node:fs').writeFileSync(${JSON.stringify(join(project,'started'))},'started')`],policy);
assert.equal(refused.completion,'not-started');assert.equal(existsSync(join(project,'started')),false);assert.equal(readFileSync(untouched,'utf8'),'unchanged');
const netProject=join(roots,'network-project');mkdirSync(netProject,{mode:0o700});
const server=createServer();let connections=0;server.on('connection',socket=>{connections++;socket.destroy();});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const port=server.address().port;
const network=await adapter.run('/usr/bin/node',['-e',`const n=require('node:net'),s=n.connect({host:'127.0.0.1',port:${port}});s.on('connect',()=>process.exit(9));s.on('error',()=>process.exit(0));setTimeout(()=>process.exit(0),1000);`],{cwd:netProject,timeoutMs:5000,namespaceJail:{mode:'required',projectDir:netProject}});
assert.equal(network.code,0,JSON.stringify(network));assert.equal(network.processIsolation.namespaceSetup,'launcher-confirmed');assert.equal(connections,0);await new Promise(resolve=>server.close(resolve));
const result={status:'PASS',archive_sha256:receipt.archive_sha256,uid:process.getuid(),installed,dist_files_verified:Object.keys(actual).length,scripts_enabled_offline_install:true,compiler_and_contributor_source_inaccessible:true,version:pkg.version,root_and_client_exports:true,recovery:recoveryResult,required_boundary:{useful:true,outside_and_read_only_writes_refused:true,shared_inode_before_entry_refused:true,network_connection_refused:true,patched_bwrap_sha256:sha(readFileSync('/opt/keep/bubblewrap/0.13.0/bwrap'))},limits:'One owned Linux x64 synthetic process fixture. No real organization login/custody, VM/production launch, paid model or independent/offsite evidence.'};
writeFileSync(join(home,'installed-result.json'),JSON.stringify(result,null,2)+'\n',{mode:0o600});console.log(JSON.stringify(result));
