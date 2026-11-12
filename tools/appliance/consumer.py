#!/usr/bin/env python3
"""Clean candidate consumer. Uses shipped controls and pre-existing ChromeDriver."""
import base64
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request


def execute(args, **options):
    try:
        return subprocess.run(args, check=True, text=True, capture_output=True, timeout=options.pop('timeout', 600),
                              env={'PATH': os.environ['PATH'], 'HOME': os.environ['HOME'], 'LANG': 'C.UTF-8'}, **options).stdout.strip()
    except subprocess.CalledProcessError as error:
        # Controlled account-free host commands only; stdout can hold the sample
        # invitation, so retain just bounded stderr for failed operations.
        raise RuntimeError('Owned consumer command failed: ' + error.stderr[:8192]) from error


def capture_file(args, path):
    """Keep guest bytes intact, including compressed data and trailing newlines."""
    with path.open('xb') as stream:
        try:
            subprocess.run(args, check=True, stdout=stream, stderr=subprocess.PIPE, timeout=600,
                           env={'PATH': os.environ['PATH'], 'HOME': os.environ['HOME'], 'LANG': 'C.UTF-8'})
        except subprocess.CalledProcessError as error:
            # This helper captures only the fixed public distribution inputs.
            # Preserve the failing file diagnostic, never the binary stdout.
            raise RuntimeError('Read-only distribution capture failed: ' + error.stderr[:8192].decode(errors='replace')) from error
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''): digest.update(block)
    return {'file': path.name, 'sha256': digest.hexdigest(), 'bytes': path.stat().st_size}


def node_directory(manifest):
    version = manifest['components']['nodeVersion']
    if not re.fullmatch(r'22\.[0-9]+\.[0-9]+', version): raise RuntimeError('Unsupported frozen Node directory')
    return 'opt/keep/node-v' + version + '-linux-x64'


def runtime_source(manifest):
    source = manifest.get('imageSource', manifest['source'])
    if not re.fullmatch(r'[0-9a-f]{40}', source) or manifest['components']['source'] != source:
        raise RuntimeError('Frozen image provenance differs from its components')
    return source


def capture_distribution(cli, state, output, manifest):
    run = [sys.executable, str(cli), 'run', str(state), '--']
    files = [capture_file(run + ['cat', '/var/lib/dpkg/status'], output / 'guest-dpkg-status')]
    files.append(capture_file(run + ['dpkg-query', '-W',
        '--showformat=${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n'], output / 'guest-packages.tsv'))
    # These are the final guest's notices and exact Keep/engine source support,
    # without any home, account or per-import credential state.
    paths = ['usr/share/doc', 'usr/share/common-licenses',
        'opt/keep/runtime/LICENSE', 'opt/keep/runtime/NOTICE', 'opt/keep/runtime/THIRD_PARTY_NOTICES.txt',
        'opt/keep/runtime/native/licenses', 'opt/keep/runtime/source-support.tar.gz',
        'opt/keep/runtime/engines/codex-generation.2/source-support.tar.gz',
        node_directory(manifest) + '/LICENSE', node_directory(manifest) + '/lib/node_modules/npm']
    files.append(capture_file(run + ['tar', '-czf', '-', '-C', '/', *paths], output / 'guest-distribution-support.tar.gz'))
    receipt = {'schema': 'keep.appliance.distribution-input/v1', 'source': manifest['source'],
        'runtimeSource': runtime_source(manifest),
        'imageSha256': manifest['files']['keep.qcow2'], 'files': files,
        'debianSourcesAcquired': False, 'noticeAndSupportPaths': paths}
    (output / 'distribution-input.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def verify_manifest_source(manifest, expected_source):
    if not expected_source or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', expected_source) or manifest['source'] != expected_source:
        raise RuntimeError('Downloaded candidate manifest differs from independently supplied frozen source')


def verify_export(exported, project_id, run_id, decision, digest, expected_tests):
    if set(exported) != {'schema', 'assurance', 'data', 'sha256'} or exported['schema'] != 'keep.proposal-export/v1' or exported['assurance'] != 'unsigned-retained-evidence':
        raise RuntimeError('Unexpected portable proposal schema')
    body = {key: exported[key] for key in ('schema', 'assurance', 'data')}
    # This fixed export schema has ASCII object keys and string/bool/null values.
    # Match src/spine/event.ts canonicalize: recursively sort keys, compact UTF-8 JSON.
    encoded = json.dumps(body, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode()
    if hashlib.sha256(encoded).hexdigest() != exported['sha256']: raise RuntimeError('Portable proposal canonical checksum mismatch')
    data = exported['data']
    if data['projectId'] != project_id or data['runId'] != run_id: raise RuntimeError('Proposal belongs to another project/run')
    if hashlib.sha256(data['proposal']['diff'].encode()).hexdigest() != digest or data['proposal']['patchSha256'] != digest:
        raise RuntimeError('Proposal patch differs from exact decided digest')
    checks = data['proposal']['checks']
    if checks['testsPassed'] is not True or checks['vettingCleared'] is not True or checks['passedTests'] != expected_tests:
        raise RuntimeError('Proposal lacks the frozen sample check results')
    matching = [item for item in data['decisions'] if item['event'] == 'project.human-proposal-decision'
                and item['decision'] == decision and item['proposalDigest'] == digest
                and isinstance(item['humanIdSha256'], str) and re.fullmatch(r'[0-9a-f]{64}', item['humanIdSha256'])]
    if not matching: raise RuntimeError('Exact human proposal decision is absent')
    wanted_status = 'refused' if decision == 'veto' else 'merged'
    if not any(item['status'] == wanted_status for item in matching): raise RuntimeError('Exact decision has no confirmed expected result')
    if decision == 'approve' and data['delivery']['workspace'] != 'merged': raise RuntimeError('Workspace approval was not recorded as merged')
    return data


def console_project_id(url):
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qs(parsed.query)
    values = query.get('projectId', [])
    if (parsed.scheme, parsed.netloc, parsed.path) != ('http', '127.0.0.1:7788', '/console/project'):
        return None
    if set(query) != {'projectId'} or len(values) != 1 or not re.fullmatch(r'[A-Za-z0-9_-]+', values[0]):
        return None
    return values[0]


def wait_for_console_navigation(read_page, previous_document, deadline, *, project_url=None, action_path=None):
    """Observe one dispatched navigation; never click, reload or resubmit here."""
    expected_id = console_project_id(project_url) if project_url else None
    if project_url and not expected_id:
        raise RuntimeError('Expected retained project URL is invalid')
    while time.monotonic() < deadline:
        page = read_page()
        if page['document'] != previous_document and page['ready'] == 'complete':
            project_id = console_project_id(page['url'])
            if project_id:
                if expected_id and project_id != expected_id:
                    raise RuntimeError('Navigation reached another project; no action retried')
                return page['url'], project_id
            parsed = urllib.parse.urlsplit(page['url'])
            if action_path and (parsed.scheme, parsed.netloc, parsed.path) == ('http', '127.0.0.1:7788', action_path):
                if expected_id and console_project_id(page.get('projectLink', '')) == expected_id:
                    return page['url'], expected_id
                raise RuntimeError('Action response lacks its expected retained project; no action retried')
            raise RuntimeError('Console navigation reached an unexpected/error page; no submission or action retried')
        time.sleep(0.1)
    raise RuntimeError('Console navigation not confirmed before deadline; inspect retained work; no submission or action retried')


def wait_for_console_page(read_page, previous_document, deadline, *, expected_url, require_control=False):
    """Observe one explicit navigation/login at its fixed route; never dispatch."""
    parsed = urllib.parse.urlsplit(expected_url)
    if (parsed.scheme, parsed.netloc) != ('http', '127.0.0.1:7788') or not (
            expected_url in ('http://127.0.0.1:7788/console', 'http://127.0.0.1:7788/console/new') or
            console_project_id(expected_url)):
        raise RuntimeError('Expected console route is invalid')
    while time.monotonic() < deadline:
        page = read_page()
        if page['document'] != previous_document and page['ready'] == 'complete':
            if page['url'] != expected_url:
                raise RuntimeError('Console navigation reached an unexpected/error route; no action retried')
            if require_control and not page['expectedControl']:
                raise RuntimeError('Completed console page lacks its authenticated/expected control; no action retried')
            return page
        time.sleep(0.1)
    raise RuntimeError('Console page navigation not confirmed before deadline; no action retried')


def failure_diagnostics(url, body, credential=None):
    parsed = urllib.parse.urlsplit(url)
    # Retain the route only: invitation, CSRF, submission and export query values
    # are unnecessary to diagnose the rendered page. Body excludes input values.
    route = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc.rsplit('@', 1)[-1], parsed.path, '', ''))
    if credential:
        body = body.replace(credential, '[redacted credential]')
    body = re.sub(r'(?i)\b[0-9a-f]{64}\b', '[redacted digest/credential]', body)
    return {'urlWithoutQuery': route, 'bodyText': body[:8192]}


CONSOLE_PAGE_STATE_SCRIPT = '''return {
  url: location.href,
  document: performance.timeOrigin,
  ready: document.readyState,
  projectLink: document.querySelector('a[href^="/console/project?projectId="]')?.href || "",
  expectedControl: !!arguments[0] && !!document.querySelector(arguments[0]),
  refresh: document.querySelector('meta[http-equiv="refresh" i]')?.getAttribute('content') ?? null,
  heading: document.querySelector('h1')?.textContent || "",
  message: document.querySelector('.intro, .notice')?.textContent || ""
}'''


APPROVAL_BOUNDARY_PROBE = r'''
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,readFileSync,rmSync} from 'node:fs';
import {dirname,join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {createBrowserProjectFixture,SAMPLE_GOAL} from '/opt/keep/runtime/dist/src/demo/browser_project_fixture.js';
import {handleGatewayRequest} from '/opt/keep/runtime/dist/src/gateway/http_gateway.js';
import {verifyProposalExport} from '/opt/keep/runtime/dist/src/audit/proposal_export.js';
const root=mkdtempSync('/home/keep/approval-boundary-');
let settled=false;
try {
  const fixture=createBrowserProjectFixture(root,{localAppliance:true,requiredJail:{
    executable:'/opt/keep/bubblewrap/0.13.0/bwrap',nodeToolchain:dirname(dirname(process.execPath))}});
  const token='appliance-boundary-fixture-only';
  const request=async(method,path,body={},query={})=>{
    const response=await handleGatewayRequest(fixture.app,{method,path,query,
      headers:{authorization:`Bearer ${token}`},body:method==='GET'?'':JSON.stringify(body)},{token});
    assert.equal(response.status,200,`${path}: ${response.body}`);
    return JSON.parse(response.body);
  };
  const started=await request('POST','/project',{goal:SAMPLE_GOAL});
  assert.ok(started.wait?.decisionId);
  const prepared=await request('POST','/project/resume',{runId:started.runId,
    approval:{decisionId:started.wait.decisionId,approved:true}});
  assert.match(prepared.proposalDigest,/^[a-f0-9]{64}$/);
  const reviewed=await request('GET','/project',{}, {runId:started.runId});
  assert.equal(reviewed.proposal.checks.testsPassed,true);
  assert.equal(reviewed.proposal.checks.passedTests.length,4);
  const workspace=join(fixture.workspaces,'project');
  const git=(cwd,...args)=>execFileSync('git',['-c','core.hooksPath=/dev/null',...args],{
    cwd,encoding:'utf8',env:{PATH:process.env.PATH,GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null'},timeout:5000});
  const before=git(workspace,'rev-parse','HEAD').trim();
  const marker='Unreviewed appliance qualification file.\n';
  writeFileSync(join(workspace,'unreviewed.txt'),marker,{flag:'wx'});
  const result=await request('POST','/project/merge',{runId:started.runId,
    decision:'approve',proposalDigest:prepared.proposalDigest});
  assert.ok(['failed','refused'].includes(result.status),JSON.stringify(result));
  assert.match(result.reason,/unreviewed|untracked/i);
  assert.equal(git(workspace,'rev-parse','HEAD').trim(),before);
  assert.equal(git(fixture.source,'rev-parse','HEAD').trim(),fixture.baseRevision);
  assert.equal(git(workspace,'diff','--cached','--name-only'),'');
  assert.equal(git(workspace,'ls-files','--','unreviewed.txt'),'');
  assert.equal(readFileSync(join(workspace,'unreviewed.txt'),'utf8'),marker);
  const exported=await request('GET','/project/export',{}, {runId:started.runId,proposalDigest:prepared.proposalDigest});
  const bundle=verifyProposalExport(JSON.stringify(exported));
  assert.equal(bundle.data.proposal.diff,reviewed.proposal.diff);
  assert.equal(bundle.data.proposal.diff.includes('unreviewed.txt'),false);
  const unresolved=fixture.app.projectRuntime.retainedJobs().filter(job=>['queued','running','reconciliation-required'].includes(job.state));
  assert.deepEqual(unresolved,[]);
  settled=true;
  assert.equal(fixture.generations(),2);
  console.log(JSON.stringify({schema:'keep.appliance.approval-boundary/v1',passed:true,
    status:result.status,checks:4,authoredResponses:fixture.generations(),requiredJail:true,
    headUnchanged:true,sourceUnchanged:true,unreviewedFileUnstaged:true,proposalExportUnchanged:true,unresolvedJobs:0}));
} finally {
  if(settled) rmSync(root,{recursive:true,force:true});
}
'''


def wait_for_console_control(read_page, project_url, deadline, credential=None):
    """Read one atomic DOM snapshot at the UI's two-second refresh cadence.

    The browser follows the page's existing meta-refresh. This observer never
    reloads, clicks, submits or repeats an approval.
    """
    expected_id = console_project_id(project_url)
    if not expected_id:
        raise RuntimeError('Expected retained project URL is invalid')
    while time.monotonic() < deadline:
        page = read_page()
        if page['ready'] == 'complete':
            if console_project_id(page['url']) != expected_id:
                raise RuntimeError('Console observation reached another/unexpected page; no action retried')
            if page['expectedControl']:
                return page
            refreshing = re.fullmatch(r'\s*2(?:\.0+)?\s*', page['refresh'] or '') is not None
            if page['heading'].strip() and not refreshing:
                detail = failure_diagnostics(page['url'], page['heading'] + '\n' + page['message'], credential)
                raise RuntimeError('Console held/failed before the expected control; no action retried: ' + json.dumps(detail))
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(2, remaining))
    raise RuntimeError('Console expected control not observed before deadline; inspect retained work; no action retried')


def main():
    bundle, output = [Path(value).resolve() for value in sys.argv[1:3]]
    output.mkdir(mode=0o700)
    cli = bundle / 'keep-appliance.py'
    manifest = json.loads((bundle / 'manifest.json').read_text())
    verify_manifest_source(manifest, os.environ.get('KC111_EXPECTED_SOURCE'))
    contract = manifest['sampleContract']
    for name in contract['sourceFiles']:
        if Path(name).name != name: raise RuntimeError('Unsupported controlled sample path contract')
    changed_files = [name for name, original in contract['sourceFiles'].items() if contract['expectedFiles'][name] != original]
    if not changed_files: raise RuntimeError('Controlled sample contract has no useful change')
    original_image_hash = manifest['files']['keep.qcow2']
    driver_path = shutil.which('chromedriver')
    if not driver_path and os.environ.get('CHROMEWEBDRIVER'):
        candidate = Path(os.environ['CHROMEWEBDRIVER']) / 'chromedriver'
        if candidate.exists(): driver_path = str(candidate)
    chrome = shutil.which('google-chrome') or shutil.which('chromium') or shutil.which('chromium-browser')
    if not driver_path or not chrome: raise RuntimeError('Existing Chrome and ChromeDriver are required for this consumer; no installation attempted')
    with socket.socket() as port_socket:
        port_socket.bind(('127.0.0.1', 0)); driver_port = port_socket.getsockname()[1]
    log = open(output / 'chromedriver.log', 'wb')
    browser_driver = subprocess.Popen([driver_path, '--port=' + str(driver_port), '--allowed-ips=127.0.0.1'], stdout=log, stderr=log,
        env={'PATH': os.environ['PATH'], 'HOME': os.environ['HOME'], 'LANG': 'C.UTF-8'})
    base = 'http://127.0.0.1:' + str(driver_port)
    session = None; active_state = None; token = None
    stages, identities = [], []
    approval_boundary = None

    def webdriver(method, path, data=None):
        req = urllib.request.Request(base + path, data=None if data is None else json.dumps(data).encode(),
                                     headers={'Content-Type': 'application/json'}, method=method)
        with urllib.request.urlopen(req, timeout=30) as response: value = json.load(response)
        if isinstance(value.get('value'), dict) and value['value'].get('error'): raise RuntimeError(str(value['value']))
        return value['value']

    def call(method, path, data=None): return webdriver(method, '/session/' + session + path, data)
    def elements(selector): return call('POST', '/elements', {'using': 'css selector', 'value': selector})
    def element(selector):
        found = elements(selector)
        if not found: raise RuntimeError('Browser element missing: ' + selector)
        return found[0]['element-6066-11e4-a52e-4f735466cecf']
    def text(selector): return call('GET', '/element/' + element(selector) + '/text')
    def content(selector): return call('POST', '/execute/sync', {'script': 'return document.querySelector(arguments[0]).textContent', 'args': [selector]})
    def click(selector): call('POST', '/element/' + element(selector) + '/click', {})
    def attribute(selector, name): return call('GET', '/element/' + element(selector) + '/attribute/' + name)
    def navigate(url, expected_control=None):
        deadline = time.monotonic() + 30
        previous = page_state()['document']
        call('POST', '/url', {'url': url})
        return wait_for_console_page(lambda: page_state(expected_control), previous, deadline,
                                     expected_url=url, require_control=expected_control is not None)
    def screenshot(name): (output / name).write_bytes(base64.b64decode(call('GET', '/screenshot')))
    def control(state, action, *args): return execute([sys.executable, str(cli), action, str(state), *args])
    def page_state(expected_control=None):
        return call('POST', '/execute/sync', {'script': CONSOLE_PAGE_STATE_SCRIPT, 'args': [expected_control]})
    def click_navigation(selector):
        previous = page_state()['document']
        click(selector)
        return previous
    def sign_in(credential):
        call('POST', '/element/' + element('input[name=token]') + '/value', {'text': credential})
        deadline = time.monotonic() + 30
        previous = click_navigation('form[action="/console/login"] button')
        # review_web's successful POST returns303 to /console. The fixed goal
        # control exists only in its authenticated sample landing/recovery form.
        return wait_for_console_page(lambda: page_state('form[action="/console/submit"] [name=goal]'),
                                     previous, deadline, expected_url='http://127.0.0.1:7788/console', require_control=True)
    def open_action_result(project_url, previous_document, action_path, deadline):
        current, _ = wait_for_console_navigation(page_state, previous_document, deadline,
                                                 project_url=project_url, action_path=action_path)
        if console_project_id(current):
            return
        target = urllib.parse.urlsplit(project_url)
        previous = click_navigation('a[href="' + target.path + '?' + target.query + '"]')
        wait_for_console_navigation(page_state, previous, deadline, project_url=project_url)
    def inspect_diff():
        if not call('GET', '/element/' + element('.diff') + '/displayed'):
            click('details:has(.diff) > summary')
        return content('.diff')

    try:
        for _ in range(100):
            try: webdriver('GET', '/status'); break
            except OSError:
                if browser_driver.poll() is not None: raise RuntimeError('Existing ChromeDriver failed to start')
                time.sleep(0.1)
        execute([sys.executable, str(cli), 'check'])
        for decision, index in [('veto', 1), ('approve', 2)]:
            state = Path.cwd() / ('instance ' + str(index))
            active_state = state
            control(state, 'start', '--port', '7788', '--ssh-port', '2222')
            before = json.loads(control(state, 'sample-status'))
            assert before['status'] == 'stopped' and before['stateRetained'] is False
            proof = json.loads(control(state, 'run', '--', '/' + node_directory(manifest) + '/bin/node', '/opt/keep/runtime/tools/appliance/guest-proof.mjs'))
            assert proof['passed'] is True and proof['source'] == runtime_source(manifest)
            assert proof['hashes']['node'] == manifest['components']['nodeExecutableSha256']
            (output / ('guest-proof-' + str(index) + '.json')).write_text(json.dumps(proof, indent=2) + '\n')
            if index == 1:
                capture_distribution(cli, state, output, manifest)
            if decision == 'approve':
                # A separate owned fixture exercises the installed negative path.
                # The browser task below keeps its normal one-decision lifecycle.
                approval_boundary = json.loads(control(state, 'run', '--', '/' + node_directory(manifest) + '/bin/node',
                    '--input-type=module', '-e', APPROVAL_BOUNDARY_PROBE))
                assert approval_boundary['passed'] is True
                (output / 'approval-boundary.json').write_text(json.dumps(approval_boundary, indent=2) + '\n')
            # A fresh clone's authorized key must be exactly this import's public key.
            guest_key = control(state, 'run', '--', 'cat', '/home/keep/.ssh/authorized_keys').strip()
            public_key = (state / 'owner-key.pub').read_text().strip()
            assert guest_key == public_key
            machine = control(state, 'run', '--', 'cat', '/etc/machine-id')
            host_key = execute(['ssh-keygen', '-lf', str(state / 'known-hosts')])
            ready = json.loads(control(state, 'sample-start'))
            assert ready['status'] == 'running'
            token = control(state, 'credential')
            assert len(token) == 64
            identities.append({'machineId': machine, 'hostKey': host_key.split()[1], 'tokenSha256': hashlib.sha256(token.encode()).hexdigest(), 'publicKeySha256': hashlib.sha256(public_key.encode()).hexdigest()})
            value = webdriver('POST', '/session', {'capabilities': {'alwaysMatch': {'browserName': 'chrome', 'goog:chromeOptions': {
                'binary': chrome, 'args': ['--headless=new', '--mute-audio', '--disable-dev-shm-usage'],
                'prefs': {'download.default_directory': str(output), 'download.prompt_for_download': False}}}}})
            session = value['sessionId']
            navigate('http://127.0.0.1:7788/console', 'input[name=token]')
            assert contract['notice'] in text('body') and 'Approval retains the reviewed workspace' in text('body')
            sign_in(token)
            assert len(elements('.project')) == 0
            assert attribute('[name=goal]', 'value') == contract['goal']
            deadline = time.monotonic() + 600
            previous = click_navigation('form[action="/console/submit"] button')
            project_url, project_id = wait_for_console_navigation(page_state, previous, deadline)
            prepare_control = 'form[action="/console/resume"] button[value=approve]'
            wait_for_console_control(lambda: page_state(prepare_control), project_url, deadline, token)
            deadline = time.monotonic() + 600
            previous = click_navigation(prepare_control)
            open_action_result(project_url, previous, '/console/resume', deadline)
            wait_for_console_control(lambda: page_state('form[action="/console/merge"]'), project_url, deadline, token)
            observed_diff = inspect_diff()
            for name in changed_files: assert 'diff --git a/' + name + ' b/' + name in observed_diff
            assert all(name in content('body') for name in contract['passedTests'])
            digest = attribute('input[name=proposalDigest]', 'value')
            run_id = attribute('form[action="/console/merge"] input[name=runId]', 'value')
            screenshot('checked-' + decision + '.png')
            deadline = time.monotonic() + 30
            previous = click_navigation('form[action="/console/merge"] button[value=' + decision + ']')
            open_action_result(project_url, previous, '/console/merge', deadline)
            previous = set(output.glob('*.json'))
            click('a[href^="/console/export?"]')
            deadline = time.monotonic() + 30
            while not (set(output.glob('*.json')) - previous):
                if time.monotonic() > deadline: raise RuntimeError('Actual browser download did not complete')
                time.sleep(0.1)
            downloaded = (set(output.glob('*.json')) - previous).pop()
            exported = json.loads(downloaded.read_text())
            data = verify_export(exported, project_id, run_id, decision, digest, contract['passedTests'])
            assert token not in downloaded.read_text()
            downloaded.rename(output / ('proposal-' + decision + '.json'))
            for name, original in contract['sourceFiles'].items():
                source = control(state, 'run', '--', 'sha256sum', '/home/keep/reviewer-sample/source/' + name).split()[0]
                workspace = control(state, 'run', '--', 'sha256sum', '/home/keep/reviewer-sample/workspaces/project/' + name).split()[0]
                assert source == hashlib.sha256(original.encode()).hexdigest()
                assert workspace == hashlib.sha256(contract['expectedFiles'][name].encode()).hexdigest()
            control(state, 'sample-stop')
            resumed = json.loads(control(state, 'sample-start'))
            assert resumed['sample']['resumed'] is True and resumed['sample']['generations'] == 0
            navigate(project_url)
            # New server session deliberately requires the retained instance credential.
            if elements('input[name=token]'):
                sign_in(token)
                navigate(project_url)
            observed_diff = inspect_diff()
            for name in changed_files: assert 'diff --git a/' + name + ' b/' + name in observed_diff
            assert elements('a[href*="/console/export?"]')
            navigate('http://127.0.0.1:7788/console/new')
            recover = element('form[action="/console/submit"] button')
            if not call('GET', '/element/' + recover + '/displayed'):
                click('details:has(form[action="/console/submit"]) > summary')
            deadline = time.monotonic() + 30
            previous = click_navigation('form[action="/console/submit"] button')
            recovered_url, recovered_id = wait_for_console_navigation(page_state, previous, deadline, project_url=project_url)
            assert recovered_url == project_url and recovered_id == project_id, 'retained sample must recover its original project'
            assert control(state, 'credential') == token
            screenshot('reopened-' + decision + '.png')
            call('DELETE', '', None); session = None
            stopped = json.loads(control(state, 'stop'))
            assert stopped['status'] == 'guest-stopped' and stopped['unresolved'] == []
            assert json.loads(control(state, 'status'))['guestRunning'] is False
            active_state = None
            stages.append({'decision': decision, 'projectId': project_id, 'runId': run_id, 'digest': digest,
                           'actualBrowser': True, 'requiredJailChecks': True, 'sourceUnchanged': True, 'restartRetained': True})
        assert all(identities[0][name] != identities[1][name] for name in identities[0])
        # Recheck the frozen base after both owned overlays, without changing it.
        execute([sys.executable, str(cli), 'check'])
        assert json.loads((bundle / 'manifest.json').read_text())['files']['keep.qcow2'] == original_image_hash
        receipt = {'schema': 'keep.appliance.clean-consumer/v1', 'passed': True, 'source': manifest['source'],
            'runtimeSource': runtime_source(manifest),
            'imageSha256': original_image_hash, 'checkoutAvailable': False, 'hostNodeNpmRustUsed': False,
            'browserDriver': execute([driver_path, '--version']), 'browser': execute([chrome, '--version']),
            'stages': stages, 'freshCloneIdentities': identities, 'approvalBoundary': approval_boundary, 'paidCalls': 0}
        (output / 'consumer.json').write_text(json.dumps(receipt, indent=2) + '\n')
        print('KC111_CONSUMER_JSON=' + json.dumps(receipt), flush=True)
    except Exception as error:
        failure = {'source': manifest['source'], 'stages': stages, 'error': str(error)}
        if session:
            try:
                page = call('POST', '/execute/sync', {'script': 'return {url: location.href, body: document.body?.innerText || ""}', 'args': []})
                failure['browser'] = failure_diagnostics(page['url'], page['body'], token)
            except Exception: pass
            try: screenshot('failure.png')
            except Exception: pass
        (output / 'failure.json').write_text(json.dumps(failure, indent=2) + '\n')
        raise
    finally:
        if session:
            try: call('DELETE', '', None)
            except Exception: pass
        if active_state:
            try: print(control(active_state, 'stop'), flush=True)
            except Exception as error: print('Owned guest stop unresolved: ' + str(error), flush=True)
        browser_driver.terminate(); browser_driver.wait(timeout=30); log.close()


if __name__ == '__main__': main()
