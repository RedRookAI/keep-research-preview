#!/usr/bin/env python3
"""Reassemble reviewed host tools around the exact frozen .29 guest image."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
ORIGINAL = {'source': '253fbca62133bef33ecc7d0c4b2192541cb55918',
 'archive': 'keep-reviewer-0.0.29-preview.1-linux-x64-253fbca62133-43181852965.tar.xz',
 'sha256': '728b565e4269f7eee371c8c55c841cac11d9c855d62b066d9fc1e0a632db7517',
 'compressedBytes': 569119212,
 'imageSha256': '0ec8468c91ebf2afabeb88c149e8d48fc85e1485211c6c8849085b52900f1897',
 'imageBytes': 1979252736,
 'diskVirtualBytes': 8589934592}
GUEST_PATHS = ['src', 'bin', 'package.json', 'package-lock.json',
               'integrations/openclaw', 'tools/reviewer_local_sample.mjs', 'tools/reviewer_node_toolchain.mjs',
               'tools/appliance/guest-control.py', 'tools/appliance/guest-proof.mjs']
HOST_FILES = {'keep-appliance.py': 'tools/appliance/keep-appliance.py',
              'qualify.py': 'tools/appliance/consumer.py', 'GUIDE.md': 'docs/reviewer-appliance.md'}


def require(condition, message):
    if not condition: raise RuntimeError(message)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''): h.update(block)
    return h.hexdigest()


def git(root, *args, **kwargs):
    return subprocess.run(['git', *args], cwd=root, check=True, **kwargs)


def assembly_source(root, image_source):
    source = git(root, 'rev-parse', 'HEAD', capture_output=True, text=True).stdout.strip()
    require(re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', source) is not None
            and source == os.environ.get('GITHUB_SHA'), 'Checkout differs from frozen assembly source')
    result = subprocess.run(['git', 'diff', '--quiet', image_source, source, '--', *GUEST_PATHS], cwd=root)
    require(result.returncode == 0, 'Guest code/package differs from frozen image source; no repack')
    return source


def extract_original(archive, destination):
    # The original format is a single flat bundle of regular files. No links,
    # devices, nested directories or additional roots are needed for this input.
    with tarfile.open(archive, 'r:xz') as stream:
        members = stream.getmembers(); names = set(); roots = set()
        for member in members:
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and '..' not in path.parts and len(path.parts) in (1, 2),
                    'Unexpected original archive path')
            require(str(path) not in names, 'Duplicate original archive member')
            names.add(str(path)); roots.add(path.parts[0])
            require(not member.mode & 0o7000, 'Unexpected original special permission bits')
            require((len(path.parts) == 1 and member.isdir())
                    or (len(path.parts) == 2 and member.isfile()), 'Unexpected original archive member type')
        require(len(roots) == 1, 'Expected one original bundle root')
        stream.extractall(destination, filter='data')
        # The data filter adds owner-write permission to regular files. Restore
        # the authenticated ordinary modes after safe extraction, including qcow2.
        for member in members: (destination / member.name).chmod(member.mode & 0o777)
    return destination / next(iter(roots))


def bundle_hashes(bundle, exclude):
    result = {}
    for path in sorted(bundle.iterdir()):
        require(path.is_file() and not path.is_symlink(), 'Unexpected bundle member')
        if path.name not in exclude: result[path.name] = digest(path)
    return result


def verify_original(bundle, original):
    manifest = json.loads((bundle / 'manifest.json').read_text())
    require(manifest.get('schema') == 'keep.appliance.bundle/v1'
            and manifest.get('source') == original['source']
            and manifest.get('components', {}).get('source') == original['source'],
            'Original manifest image provenance differs')
    file_hashes = bundle_hashes(bundle, {'manifest.json', 'SHA256SUMS'})
    require(manifest['files'] == file_hashes,
            'Original manifest file hashes differ')
    descriptor_hashes = {**file_hashes, 'manifest.json': digest(bundle / 'manifest.json')}
    sums = ''.join(value + '  ' + name + '\n'
                   for name, value in sorted(descriptor_hashes.items()))
    require((bundle / 'SHA256SUMS').read_text() == sums, 'Original bundle checksum descriptor differs')
    image = bundle / 'keep.qcow2'
    require(file_hashes['keep.qcow2'] == original['imageSha256'] and image.stat().st_size == original['imageBytes'],
            'Original image bytes differ')
    require(manifest['profile']['diskVirtualBytes'] == original['diskVirtualBytes'],
            'Original image virtual size differs')
    receipt = json.loads((bundle / 'image-build.json').read_text())
    require(receipt == manifest['components'], 'Original guest build receipt differs from components')
    return manifest


def repack(archive, candidate_path, output, root=ROOT, original=ORIGINAL):
    candidate = json.loads(candidate_path.read_text())
    require(candidate.get('schema') == 'keep.appliance.candidate/v1'
            and all(candidate.get(key) == value for key, value in original.items()),
            'Original candidate receipt differs from approved frozen input')
    require(digest(archive) == original['sha256'] and archive.stat().st_size == original['compressedBytes'],
            'Original archive hash or size differs')
    source = assembly_source(root, original['source'])
    with tempfile.TemporaryDirectory(prefix='kc111-repack-', dir=root) as temporary:
        bundle = extract_original(archive, Path(temporary))
        manifest = verify_original(bundle, original)
        image_mode = stat.S_IMODE((bundle / 'keep.qcow2').stat().st_mode)
        require(not (bundle / 'HOST_SOURCE.tar.gz').exists(), 'Original already contains host source assembly')
        for name, repository_path in HOST_FILES.items():
            entry = git(root, 'ls-tree', source, '--', repository_path, capture_output=True, text=True).stdout
            require(entry.startswith(('100644 blob ', '100755 blob ')), 'Host source must be a tracked regular file')
            data = git(root, 'show', source + ':' + repository_path, capture_output=True).stdout
            destination = bundle / name
            destination.write_bytes(data)
            destination.chmod(int(entry.split()[0], 8) & 0o777)
        with (bundle / 'HOST_SOURCE.tar.gz').open('xb') as stream:
            git(root, 'archive', '--format=tar.gz', source, stdout=stream)
        (bundle / 'HOST_SOURCE.tar.gz').chmod(0o644)
        file_hashes = bundle_hashes(bundle, {'manifest.json', 'SHA256SUMS'})
        require(file_hashes['keep.qcow2'] == original['imageSha256']
                and stat.S_IMODE((bundle / 'keep.qcow2').stat().st_mode) == image_mode,
                'Image bytes or mode changed during repack')
        manifest.update(source=source, sourceAssemblySHA=source, imageSource=original['source'])
        manifest['files'] = file_hashes
        (bundle / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        descriptor_hashes = {**file_hashes, 'manifest.json': digest(bundle / 'manifest.json')}
        (bundle / 'SHA256SUMS').write_text(''.join(value + '  ' + name + '\n'
            for name, value in sorted(descriptor_hashes.items())))
        output.mkdir(mode=0o700)
        archive_name = bundle.name + '-' + source[:12] + '-' + os.environ['GITHUB_RUN_ID'] + '-repack.tar.xz'
        destination = output / archive_name
        subprocess.run(['tar', '-cJf', str(destination), '-C', temporary, bundle.name], check=True,
                       env={**os.environ, 'XZ_OPT': '-T1 -1'})
        result = {'schema': 'keep.appliance.candidate/v1', 'source': source,
                  'sourceAssemblySHA': source, 'imageSource': original['source'],
                  'archive': archive_name, 'sha256': digest(destination),
                  'compressedBytes': destination.stat().st_size,
                  'imageSha256': original['imageSha256'], 'imageBytes': original['imageBytes'],
                  'diskVirtualBytes': original['diskVirtualBytes'],
                  'sourceFreezeRequired': True, 'consumerPassed': False}
        (output / 'candidate.json').write_text(json.dumps(result, indent=2) + '\n')
        (output / 'SHA256SUMS').write_text(result['sha256'] + '  ' + archive_name + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT / 'appliance-output')
    args = parser.parse_args()
    os.umask(0o077)
    result = repack(args.archive.resolve(), args.candidate.resolve(), args.output.resolve())
    print('KC111_CANDIDATE_JSON=' + json.dumps(result))


if __name__ == '__main__': main()
