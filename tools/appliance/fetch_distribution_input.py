#!/usr/bin/env python3
"""Fetch one exact owned consumer receipt archive, never an appliance image."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import urllib.request
import zipfile

REPOSITORY = 'RedRookAI/keep-research-preview'
FILES = {'consumer.json', 'distribution-input.json', 'guest-dpkg-status', 'guest-packages.tsv', 'guest-distribution-support.tar.gz'}
CAPTURE_FILES = (FILES - {'consumer.json'}) | {'guest-proof-1.json'}
PURPOSES = {'qualified-consumer', 'captured-distribution'}


def api(path, binary=False):
    request = urllib.request.Request('https://api.github.com/repos/' + REPOSITORY + path,
        headers={'Accept': 'application/octet-stream' if binary else 'application/vnd.github+json', 'User-Agent': 'Keep-source-companion'})
    request.add_unredirected_header('Authorization', 'Bearer ' + os.environ['GITHUB_TOKEN'])
    with urllib.request.urlopen(request, timeout=600) as response:
        return response.read() if binary else json.load(response)


def unpack(data, output, purpose='qualified-consumer'):
    """Extract only fixed small evidence names, refusing duplicate/ambiguous paths."""
    if purpose not in PURPOSES: raise RuntimeError('Unknown source capture purpose')
    wanted = FILES if purpose == 'qualified-consumer' else CAPTURE_FILES
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        selected = {}
        for item in archive.infolist():
            if item.filename in wanted:
                if item.filename in selected or item.is_dir(): raise RuntimeError('Duplicate consumer evidence name')
                selected[item.filename] = item
        if set(selected) != wanted: raise RuntimeError('Consumer artifact lacks final distribution evidence')
        output.mkdir(mode=0o700)
        for name, item in selected.items():
            with (output / name).open('xb') as stream, archive.open(item) as source:
                for block in iter(lambda: source.read(1024 * 1024), b''): stream.write(block)


def verify(output, source, image, purpose='qualified-consumer'):
    if purpose not in PURPOSES: raise RuntimeError('Unknown source capture purpose')
    receipt = json.loads((output / 'distribution-input.json').read_text())
    if receipt['source'] != source or receipt['imageSha256'] != image: raise RuntimeError('Consumer source/image differs from independently supplied identity')
    if purpose == 'qualified-consumer':
        consumer = json.loads((output / 'consumer.json').read_text())
        if consumer['source'] != source or consumer['imageSha256'] != image: raise RuntimeError('Consumer source/image differs from independently supplied identity')
        if consumer['schema'] != 'keep.appliance.clean-consumer/v1' or consumer['passed'] is not True or consumer['paidCalls'] != 0:
            raise RuntimeError('Exact account-free clean consumer did not pass')
    else:
        proof = json.loads((output / 'guest-proof-1.json').read_text())
        if proof['schema'] != 'keep.appliance.guest-proof/v1' or proof['passed'] is not True or proof['source'] != source or proof['modelCalls'] != 0 or type(proof['uid']) is not int or proof['uid'] <= 0 or proof['arch'] != 'x64':
            raise RuntimeError('Captured distribution lacks a confirmed account-free guest proof')
    if receipt['schema'] != 'keep.appliance.distribution-input/v1': raise RuntimeError('Unexpected distribution receipt')
    expected = FILES - {'consumer.json', 'distribution-input.json'}
    if len(receipt['files']) != len(expected) or {item['file'] for item in receipt['files']} != expected:
        raise RuntimeError('Incomplete or duplicate distribution input index')
    for item in receipt['files']:
        path = output / item['file']
        if path.stat().st_size != item['bytes'] or hashlib.sha256(path.read_bytes()).hexdigest() != item['sha256']:
            raise RuntimeError('Captured guest distribution bytes differ')
    return receipt


def verify_run(run, workflow_source, purpose='qualified-consumer'):
    if purpose not in PURPOSES: raise RuntimeError('Unknown source capture purpose')
    conclusion_ok = run['conclusion'] == 'success' if purpose == 'qualified-consumer' else run.get('status') == 'completed' and run['conclusion'] in ('success', 'failure')
    if not re.fullmatch('[0-9a-f]{40}', workflow_source or '') or run['head_sha'] != workflow_source or not conclusion_ok:
        raise RuntimeError('Owned consumer run did not pass at the independently selected qualification workflow')


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true': raise RuntimeError('Disposable CI only')
    run_id, artifact_id = int(os.environ['KC111_CONSUMER_RUN']), int(os.environ['KC111_CONSUMER_ARTIFACT'])
    source, image, digest = [os.environ[name] for name in ['KC111_EXPECTED_SOURCE', 'KC111_IMAGE_SHA256', 'KC111_ARTIFACT_SHA256']]
    workflow_source = os.environ['KC111_EXPECTED_CONSUMER_WORKFLOW_SOURCE']
    purpose = os.environ.get('KC111_CAPTURE_PURPOSE', 'qualified-consumer')
    if not re.fullmatch('[0-9a-f]{40}', source) or not all(re.fullmatch('[0-9a-f]{64}', x) for x in [image, digest]):
        raise RuntimeError('Exact source and SHA256 identities are required')
    run = api('/actions/runs/' + str(run_id))
    verify_run(run, workflow_source, purpose)
    artifact = api('/actions/artifacts/' + str(artifact_id))
    if artifact['workflow_run']['id'] != run_id or artifact['name'] != 'kc111-consumer-evidence' or artifact['expired'] or artifact.get('digest') != 'sha256:' + digest:
        raise RuntimeError('Consumer artifact differs from independently selected owned record')
    data = api('/actions/artifacts/' + str(artifact_id) + '/zip', binary=True)
    if hashlib.sha256(data).hexdigest() != digest: raise RuntimeError('Downloaded consumer artifact checksum mismatch')
    output = Path('distribution-input'); unpack(data, output, purpose); receipt = verify(output, source, image, purpose)
    (output / 'custody.json').write_text(json.dumps({'schema': 'keep.appliance.distribution-custody/v1', 'consumerRun': run_id,
        'artifactId': artifact_id, 'artifactSha256': digest, 'source': source, 'imageSha256': image,
        'consumerWorkflowSource': workflow_source, 'scriptSource': os.environ['GITHUB_SHA'],
        'purpose': purpose, 'consumerQualified': purpose == 'qualified-consumer'}, indent=2) + '\n')
    print('KC111_DISTRIBUTION_INPUT_JSON=' + json.dumps(receipt))


if __name__ == '__main__': main()
