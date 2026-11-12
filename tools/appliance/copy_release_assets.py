#!/usr/bin/env python3
"""Copy a frozen, qualified asset selection between exact existing drafts. CI only."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.parse
import urllib.request

REPOSITORY = 'RedRookAI/keep-research-preview'
SOURCE_RELEASE_ID = 442592040
CHECKSUM_NAME = 'KEEP-RELEASE-SHA256SUMS'
SOURCE_FILES = {'source-index.json', 'distribution-input.json', 'guest-dpkg-status',
                'guest-packages.tsv', 'guest-distribution-support.tar.gz'}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def filename(value):
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]*', value),
            'Unsafe asset filename')
    return value


def frozen(plan):
    require(plan.get('schema') == 'keep.appliance.release-copy/v1' and plan.get('ready') is True,
            'Asset selection is not frozen/ready; no transfer')
    require(plan['repository'] == REPOSITORY, 'Wrong repository')
    for side in ('sourceRelease', 'destinationRelease'):
        release = plan[side]
        require(type(release['id']) is int and release['id'] > 0 and
                isinstance(release['tag'], str) and release['tag'] and
                re.fullmatch('[0-9a-f]{40}', release['target'] or ''), 'Incomplete exact draft identity')
    require(plan['sourceRelease']['id'] == SOURCE_RELEASE_ID and
            plan['destinationRelease']['id'] != SOURCE_RELEASE_ID and
            plan['destinationRelease']['tag'] != plan['sourceRelease']['tag'], 'Wrong source/destination draft')
    require(re.fullmatch('[0-9a-f]{40}', plan['imageSource'] or '') and
            re.fullmatch('[0-9a-f]{64}', plan['imageSha256'] or ''), 'Missing frozen image identity')
    assets = plan['assets']
    require(isinstance(assets, list) and assets, 'No selected assets')
    for asset in assets:
        filename(asset['name'])
        require(type(asset['id']) is int and asset['id'] > 0 and
                type(asset['bytes']) is int and 0 <= asset['bytes'] < 2 * 1024 ** 3 and
                re.fullmatch('[0-9a-f]{64}', asset['sha256']), 'Invalid exact asset identity/provider size')
    require(len({a['id'] for a in assets}) == len(assets) == len({a['name'] for a in assets}),
            'Duplicate selected asset identity/name')
    names = {a['name'] for a in assets}
    require(CHECKSUM_NAME not in names and SOURCE_FILES | {'SHA256SUMS', plan['archive']} <= names,
            'Missing archive/source metadata or checksum filename collision')
    qualification = plan['qualification']
    require(qualification['receiptAsset'] in names and qualification['receiptAsset'] != plan['archive'] and
            type(qualification['runId']) is int and qualification['runId'] > 0 and
            type(qualification['artifactId']) is int and qualification['artifactId'] > 0 and
            re.fullmatch('[0-9a-f]{40}', qualification['workflowSource'] or '') and
            re.fullmatch('[0-9a-f]{64}', qualification['artifactSha256'] or ''),
            'Missing separate frozen actual qualification receipt/custody')


def release_matches(actual, expected):
    require(actual['id'] == expected['id'] and actual['draft'] is True and
            actual['tag_name'] == expected['tag'] and actual['target_commitish'] == expected['target'],
            'Release differs from exact existing draft identity')


def asset_matches(actual, wanted, *, selected_id=False):
    require(actual['name'] == wanted['name'] and actual['size'] == wanted['bytes'] and
            actual.get('digest') == 'sha256:' + wanted['sha256'] and
            (not selected_id or actual['id'] == wanted['id']), 'Asset identity differs: ' + wanted['name'])


def indexed_assets(release):
    assets = release['assets']
    require(len({a['name'] for a in assets}) == len(assets) == len({a['id'] for a in assets}),
            'Duplicate provider asset identity/name')
    return {a['name']: a for a in assets}


def destination_matches(actual, plan, wanted):
    release_matches(actual, plan['destinationRelease'])
    existing = indexed_assets(actual)
    require(existing.keys() <= wanted.keys(), 'Unselected destination asset; no writes')
    for name, asset in existing.items():
        asset_matches(asset, wanted[name])
    return existing


def source_closure(plan, index, checksums):
    require(index['schema'] == 'keep.appliance.debian-source-companion/v1' and
            index['source'] == plan['imageSource'] and index['imageSha256'] == plan['imageSha256'] and
            index['complete'] is True and index['planOnly'] is False and not index['missing'],
            'Source companion is incomplete or belongs to another image')
    names = list(SOURCE_FILES) + [filename(a['file']) for a in index['assets']]
    require(len(names) == len(set(names)), 'Duplicate source closure file')
    parsed = {}
    for line in checksums.splitlines():
        digest, name = line.split('  ', 1)
        filename(name)
        require(name not in parsed, 'Duplicate source checksum filename')
        parsed[name] = digest
    selected = {a['name']: a for a in plan['assets']}
    require(set(parsed) == set(names) and set(names) <= selected.keys(), 'Selected source closure is incomplete')
    require(all(selected[n]['sha256'] == parsed[n] for n in names), 'Source checksum differs from frozen selection')
    for asset in index['assets']:
        actual = selected[asset['file']]
        require(actual['sha256'] == asset['sha256'] and actual['bytes'] == asset['bytes'],
                'Source part identity differs from index')


class GitHub:
    def __init__(self, token):
        self.token = token

    def get(self, suffix, accept='application/vnd.github+json'):
        request = urllib.request.Request('https://api.github.com/repos/' + REPOSITORY + suffix,
            headers={'Accept': accept, 'User-Agent': 'Keep-frozen-release-copy/1',
                     'X-GitHub-Api-Version': '2022-11-28'})
        # API asset downloads redirect to storage; never forward the credential.
        request.add_unredirected_header('Authorization', 'Bearer ' + self.token)
        return urllib.request.urlopen(request, timeout=600)

    def json(self, suffix):
        with self.get(suffix) as response:
            return json.load(response)

    def release(self, release_id):
        prefix = '/releases/' + str(release_id)
        release = self.json(prefix)
        assets, page = [], 1
        while True:
            batch = self.json(prefix + '/assets?per_page=100&page=' + str(page))
            assets.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        release['assets'] = assets
        return release

    def download(self, asset_id, output, expected_bytes):
        with self.get('/releases/assets/' + str(asset_id), 'application/octet-stream') as response, output.open('xb') as stream:
            size = 0
            for block in iter(lambda: response.read(1024 * 1024), b''):
                size += len(block)
                require(size <= expected_bytes, 'Download exceeds frozen asset size')
                stream.write(block)

    def upload(self, release_id, wanted, path):
        connection = http.client.HTTPSConnection('uploads.github.com', timeout=600)
        try:
            endpoint = '/repos/' + REPOSITORY + '/releases/' + str(release_id) + '/assets?'
            connection.putrequest('POST', endpoint + urllib.parse.urlencode({'name': wanted['name']}))
            for name, value in {'Authorization': 'Bearer ' + self.token, 'User-Agent': 'Keep-frozen-release-copy/1',
                                'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/octet-stream',
                                'Content-Length': str(wanted['bytes'])}.items():
                connection.putheader(name, value)
            connection.endheaders()
            with path.open('rb') as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    connection.send(block)
            response = connection.getresponse()
            body = response.read()
            require(response.status == 201, 'Upload not confirmed: HTTP' + str(response.status))
            return json.loads(body)
        finally:
            connection.close()

    def asset(self, asset_id):
        return self.json('/releases/assets/' + str(asset_id))


def verified_download(provider, wanted, path):
    provider.download(wanted['id'], path, wanted['bytes'])
    h, size = hashlib.sha256(), 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block); size += len(block)
    require(size == wanted['bytes'] and h.hexdigest() == wanted['sha256'],
            'Downloaded bytes differ: ' + wanted['name'])


def copy_assets(plan, provider, work, emit):
    frozen(plan)
    source = provider.release(plan['sourceRelease']['id'])
    release_matches(source, plan['sourceRelease'])
    source_assets = indexed_assets(source)
    selected = {a['name']: a for a in plan['assets']}
    for name, asset in selected.items():
        require(name in source_assets, 'Selected source asset missing: ' + name)
        asset_matches(source_assets[name], asset, selected_id=True)
    checksum_bytes = ''.join(a['sha256'] + '  ' + name + '\n' for name, a in sorted(selected.items())).encode()
    checksum = {'name': CHECKSUM_NAME, 'bytes': len(checksum_bytes), 'sha256': sha256(checksum_bytes)}
    wanted = {**selected, CHECKSUM_NAME: checksum}
    destination_matches(provider.release(plan['destinationRelease']['id']), plan, wanted)
    # Verify full closure from small exact source records before any upload.
    for name in ('source-index.json', 'SHA256SUMS'):
        verified_download(provider, selected[name], work / name)
    source_closure(plan, json.loads((work / 'source-index.json').read_text()), (work / 'SHA256SUMS').read_text())
    (work / CHECKSUM_NAME).write_bytes(checksum_bytes)
    emit({'state': 'admitted', 'sourceRelease': plan['sourceRelease'], 'destinationRelease': plan['destinationRelease']})
    results = {}
    for name, asset in wanted.items():
        path = work / name
        if not path.exists():
            verified_download(provider, asset, path)
        # Recheck exact draft and all conflicts immediately before each potential write.
        existing = destination_matches(provider.release(plan['destinationRelease']['id']), plan, wanted)
        if name in existing:
            actual = existing[name]
        else:
            emit({'state': 'upload-intent', 'name': name, 'sha256': asset['sha256'], 'bytes': asset['bytes']})
            try:
                actual = provider.upload(plan['destinationRelease']['id'], asset, path)
                asset_matches(actual, asset)
                actual = provider.asset(actual['id'])
                asset_matches(actual, asset)
            except Exception:
                emit({'state': 'upload-unconfirmed', 'name': name})
                raise RuntimeError('Upload outcome unconfirmed for ' + name + '; inspect exact draft before any retry') from None
            emit({'state': 'upload-confirmed', 'name': name, 'id': actual['id']})
        results[name] = {**asset, 'id': actual['id']}
        if name in selected:
            results[name]['sourceAssetId'] = selected[name]['id']
        path.unlink()
    final = destination_matches(provider.release(plan['destinationRelease']['id']), plan, wanted)
    require(final.keys() == wanted.keys(), 'Final draft asset set differs')
    for name in wanted:
        require(final[name]['id'] == results[name]['id'], 'Final asset ID changed')
    release_matches(provider.release(plan['sourceRelease']['id']), plan['sourceRelease'])
    receipt = {'state': 'complete', 'schema': 'keep.appliance.release-copy-result/v1',
               'sourceRelease': plan['sourceRelease'], 'destinationRelease': plan['destinationRelease'], 'draft': True,
               'imageSource': plan['imageSource'], 'imageSha256': plan['imageSha256'],
               'qualification': plan['qualification'], 'assets': results}
    emit(receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and args.apply, 'Explicit disposable CI transfer only')
    raw = args.manifest.read_bytes(); plan = json.loads(raw)
    frozen(plan)  # ready=false performs no API requests or writes.
    with args.receipt.open('x') as journal:
        def emit(record):
            journal.write(json.dumps(record, sort_keys=True) + '\n'); journal.flush(); os.fsync(journal.fileno())
        emit({'state': 'selected', 'manifestSha256': sha256(raw), 'scriptSource': os.environ['GITHUB_SHA']})
        with tempfile.TemporaryDirectory(prefix='keep-release-copy-') as temporary:
            result = copy_assets(plan, GitHub(os.environ['GITHUB_TOKEN']), Path(temporary), emit)
        print('KC111_RELEASE_COPY_JSON=' + json.dumps(result))


if __name__ == '__main__':
    main()
