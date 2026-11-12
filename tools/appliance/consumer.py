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
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=options.pop('timeout', 600),
                          env={'PATH': os.environ['PATH'], 'HOME': os.environ['HOME'], 'LANG': 'C.UTF-8'}, **options).stdout.strip()


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
    session = None; active_state = None
    stages, identities = [], []

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
    def navigate(url): call('POST', '/url', {'url': url})
    def screenshot(name): (output / name).write_bytes(base64.b64decode(call('GET', '/screenshot')))
    def control(state, action, *args): return execute([sys.executable, str(cli), action, str(state), *args])
    def open_action_result(project_url):
        current = urllib.parse.urlsplit(call('GET', '/url'))
        target = urllib.parse.urlsplit(project_url)
        if current.path == target.path and urllib.parse.parse_qs(current.query).get('projectId') == urllib.parse.parse_qs(target.query).get('projectId'):
            return
        click('a[href^="/console/project?projectId="]')
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
            proof = json.loads(control(state, 'run', '--', '/opt/keep/node-v22.23.4-linux-x64/bin/node', '/opt/keep/runtime/tools/appliance/guest-proof.mjs'))
            assert proof['passed'] is True and proof['source'] == manifest['source']
            (output / ('guest-proof-' + str(index) + '.json')).write_text(json.dumps(proof, indent=2) + '\n')
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
            navigate('http://127.0.0.1:7788/console')
            assert contract['notice'] in text('body') and 'approval retains the reviewed workspace' in text('body')
            call('POST', '/element/' + element('input[name=token]') + '/value', {'text': token})
            click('form[action="/console/login"] button')
            assert len(elements('.project')) == 0
            assert attribute('[name=goal]', 'value') == contract['goal']
            click('form[action="/console/submit"] button')
            project_url = call('GET', '/url')
            project_id = urllib.parse.parse_qs(urllib.parse.urlsplit(project_url).query)['projectId'][0]
            deadline = time.monotonic() + 600
            while time.monotonic() < deadline:
                call('POST', '/refresh', {})
                if elements('form[action="/console/resume"] button[value=approve]'): break
                time.sleep(0.1)
            click('form[action="/console/resume"] button[value=approve]'); open_action_result(project_url)
            deadline = time.monotonic() + 600
            while time.monotonic() < deadline:
                call('POST', '/refresh', {})
                if elements('form[action="/console/merge"]'): break
                if elements('form[action="/console/resume"] button[value=approve]'):
                    click('form[action="/console/resume"] button[value=approve]'); open_action_result(project_url)
                time.sleep(0.1)
            observed_diff = inspect_diff()
            for name in changed_files: assert 'diff --git a/' + name + ' b/' + name in observed_diff
            assert all(name in content('body') for name in contract['passedTests'])
            digest = attribute('input[name=proposalDigest]', 'value')
            run_id = attribute('form[action="/console/merge"] input[name=runId]', 'value')
            screenshot('checked-' + decision + '.png')
            click('form[action="/console/merge"] button[value=' + decision + ']')
            open_action_result(project_url)
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
                call('POST', '/element/' + element('input[name=token]') + '/value', {'text': token})
                click('form[action="/console/login"] button'); navigate(project_url)
            observed_diff = inspect_diff()
            for name in changed_files: assert 'diff --git a/' + name + ' b/' + name in observed_diff
            assert elements('a[href*="/console/export?"]')
            navigate('http://127.0.0.1:7788/console/new')
            recover = element('form[action="/console/submit"] button')
            if not call('GET', '/element/' + recover + '/displayed'):
                click('details:has(form[action="/console/submit"]) > summary')
            click('form[action="/console/submit"] button')
            assert call('GET', '/url') == project_url, 'retained sample must recover its original project'
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
            'imageSha256': original_image_hash, 'checkoutAvailable': False, 'hostNodeNpmRustUsed': False,
            'browserDriver': execute([driver_path, '--version']), 'browser': execute([chrome, '--version']),
            'stages': stages, 'freshCloneIdentities': identities, 'paidCalls': 0}
        (output / 'consumer.json').write_text(json.dumps(receipt, indent=2) + '\n')
        print('KC111_CONSUMER_JSON=' + json.dumps(receipt), flush=True)
    except Exception as error:
        (output / 'failure.json').write_text(json.dumps({'source': manifest['source'], 'stages': stages, 'error': str(error)}, indent=2) + '\n')
        if session:
            try: screenshot('failure.png')
            except Exception: pass
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
