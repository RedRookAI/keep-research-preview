#!/usr/bin/env python3
"""Retain a complete exact-image source companion in the reviewed private draft."""
import json
import os
import re
from pathlib import Path
import subprocess

from upload_candidate import api, digest, REPOSITORY


def verified_files(output, source, image):
    index = json.loads((output / 'source-index.json').read_text())
    if index['schema'] != 'keep.appliance.debian-source-companion/v1' or index['source'] != source or index['imageSha256'] != image:
        raise RuntimeError('Source companion belongs to another image/source')
    if index['complete'] is not True or index['planOnly'] is not False or index['missing']:
        raise RuntimeError('Source companion is incomplete; no upload')
    names = ['source-index.json', 'distribution-input.json', 'guest-dpkg-status', 'guest-packages.tsv', 'guest-distribution-support.tar.gz']
    names += [asset['file'] for asset in index['assets']]
    if len(names) != len(set(names)): raise RuntimeError('Duplicate source companion filename')
    records = {}
    for name in names:
        path = output / name
        if Path(name).name != name or path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            raise RuntimeError('Invalid source companion file')
        size = path.stat().st_size
        if size >= 2 * 1024 ** 3: raise RuntimeError('Source asset exceeds existing provider limit')
        records[name] = {'sha256': digest(path), 'bytes': size}
    checksums = {}
    for line in (output / 'SHA256SUMS').read_text().splitlines():
        value, name = line.split('  ', 1)
        if name in checksums: raise RuntimeError('Duplicate source checksum filename')
        checksums[name] = value
    if checksums != {name: record['sha256'] for name, record in records.items()}:
        raise RuntimeError('Source checksum list differs from frozen files')
    for asset in index['assets']:
        if records[asset['file']] != {'sha256': asset['sha256'], 'bytes': asset['bytes']}:
            raise RuntimeError('Source archive changed after indexing')
    return records


def verify_destination(release, release_id, tag, assembly_source):
    if not re.fullmatch('[0-9a-f]{40}', assembly_source): raise RuntimeError('Explicit frozen release assembly source required')
    if release['id'] != release_id or release['draft'] is not True or release['tag_name'] != tag or release['target_commitish'] != assembly_source:
        raise RuntimeError('Destination differs from exact reviewed assembly draft')


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true': raise RuntimeError('Disposable CI only')
    output = Path('source-output')
    source, image = os.environ['KC111_EXPECTED_SOURCE'], os.environ['KC111_IMAGE_SHA256']
    files = verified_files(output, source, image)
    files['SHA256SUMS'] = {'sha256': digest(output / 'SHA256SUMS'), 'bytes': (output / 'SHA256SUMS').stat().st_size}
    release_id = int(os.environ['KC111_DRAFT_RELEASE_ID']); tag = os.environ['KC111_DRAFT_RELEASE_TAG']
    assembly_source = os.environ['KC111_DRAFT_TARGET_SOURCE']
    release = api('/releases/' + str(release_id))
    verify_destination(release, release_id, tag, assembly_source)
    existing = {asset['name']: asset for asset in release['assets']}
    # Check ALL conflicts before uploading anything. Existing exact assets are reusable.
    for name, wanted in files.items():
        asset = existing.get(name)
        if asset and (asset.get('digest') != 'sha256:' + wanted['sha256'] or asset['size'] != wanted['bytes']):
            raise RuntimeError('Existing draft source asset differs; no overwrite: ' + name)
    for name in files:
        if name not in existing:
            subprocess.run(['gh', 'release', 'upload', tag, str(output / name), '--repo', REPOSITORY], check=True,
                           env={**os.environ, 'GH_TOKEN': os.environ['GITHUB_TOKEN']}, timeout=600)
    actual = api('/releases/' + str(release_id))
    verify_destination(actual, release_id, tag, assembly_source)
    assets = {asset['name']: asset for asset in actual['assets']}
    for name, wanted in files.items():
        if assets[name]['digest'] != 'sha256:' + wanted['sha256'] or assets[name]['size'] != wanted['bytes']:
            raise RuntimeError('Transferred source identity differs')
    receipt = {'schema': 'keep.appliance.source-transfer/v1', 'source': source, 'imageSha256': image, 'assemblySource': assembly_source, 'scriptSource': os.environ['GITHUB_SHA'],
        'releaseId': release_id, 'tag': tag, 'draft': True,
        'assets': {name: {**wanted, 'id': assets[name]['id']} for name, wanted in files.items()}}
    Path('source-transfer.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print('KC111_SOURCE_TRANSFER_JSON=' + json.dumps(receipt))


if __name__ == '__main__': main()
