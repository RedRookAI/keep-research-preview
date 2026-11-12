#!/usr/bin/env python3
"""Upload only to the exact operator-created draft release; never create/publish one."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import urllib.parse
import urllib.request

REPOSITORY = 'RedRookAI/keep-research-preview'


def api(path):
    request = urllib.request.Request('https://api.github.com/repos/' + REPOSITORY + path,
        headers={'Accept': 'application/vnd.github+json', 'Authorization': 'Bearer ' + os.environ['GITHUB_TOKEN'], 'User-Agent': 'Keep-candidate-uploader'})
    with urllib.request.urlopen(request, timeout=60) as response: return json.load(response)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''): h.update(block)
    return h.hexdigest()


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true': raise RuntimeError('CI-only explicit draft transfer')
    release_id = int(os.environ['KC111_DRAFT_RELEASE_ID'])
    expected_tag = os.environ['KC111_DRAFT_RELEASE_TAG']
    release = api('/releases/' + str(release_id))
    if release['id'] != release_id or release['draft'] is not True or release['tag_name'] != expected_tag:
        raise RuntimeError('Destination differs from the reviewed owned draft; no release mutation')
    output = Path('appliance-output')
    candidate = json.loads((output / 'candidate.json').read_text())
    if candidate['source'] != os.environ['GITHUB_SHA']: raise RuntimeError('Candidate source differs from frozen build')
    existing = {asset['name']: asset for asset in release['assets']}
    results = {}
    inputs = [(output / candidate['archive'], candidate['archive']),
              (output / 'candidate.json', candidate['archive'] + '.candidate.json'),
              (output / 'SHA256SUMS', candidate['archive'] + '.sha256')]
    for path, name in inputs:
        wanted = digest(path)
        if path.stat().st_size >= 2 * 1024 ** 3: raise RuntimeError('Candidate exceeds GitHub release per-asset limit')
        if name in existing:
            asset = existing[name]
            if asset.get('digest') != 'sha256:' + wanted or asset['size'] != path.stat().st_size:
                raise RuntimeError('An immutable draft asset already has this name with different bytes; no overwrite')
        else:
            upload = urllib.parse.urlsplit(release['upload_url'].split('{', 1)[0])
            if upload.scheme != 'https' or upload.hostname != 'uploads.github.com': raise RuntimeError('Unexpected release upload endpoint')
            connection = http.client.HTTPSConnection(upload.hostname, timeout=600)
            try:
                connection.putrequest('POST', upload.path + '?' + urllib.parse.urlencode({'name': name}))
                connection.putheader('Authorization', 'Bearer ' + os.environ['GITHUB_TOKEN'])
                connection.putheader('User-Agent', 'Keep-candidate-uploader')
                connection.putheader('Content-Type', 'application/octet-stream')
                connection.putheader('Content-Length', str(path.stat().st_size)); connection.endheaders()
                with path.open('rb') as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b''): connection.send(block)
                response = connection.getresponse(); body = response.read()
                if response.status != 201: raise RuntimeError('Draft upload failed: HTTP' + str(response.status) + ' ' + body[:1000].decode(errors='replace'))
                asset = json.loads(body)
            finally: connection.close()
        if asset.get('digest') not in (None, 'sha256:' + wanted) or asset['size'] != path.stat().st_size:
            raise RuntimeError('Uploaded asset identity differs from exact candidate')
        results[name] = {'id': asset['id'], 'sha256': wanted, 'bytes': path.stat().st_size, 'providerDigest': asset.get('digest')}
    selected = results[candidate['archive']]
    receipt = {'schema': 'keep.appliance.draft-transfer/v1', 'releaseId': release_id, 'tag': expected_tag,
               'draft': True, 'source': candidate['source'], 'assets': results}
    (output / 'draft-transfer.json').write_text(json.dumps(receipt, indent=2) + '\n')
    with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
        for key, value in {'asset_id': selected['id'], 'asset_sha256': selected['sha256'], 'asset_name': candidate['archive'], 'source': candidate['source']}.items():
            stream.write(key + '=' + str(value) + '\n')
    print('KC111_DRAFT_TRANSFER_JSON=' + json.dumps(receipt))


if __name__ == '__main__': main()
