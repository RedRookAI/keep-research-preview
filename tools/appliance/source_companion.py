#!/usr/bin/env python3
"""Exact Debian source companion, run AFTER the real consumer capture on disposable CI.

python3 tools/appliance/source_companion.py --input CONSUMER_DIR \
  --expected-source FROZEN_SOURCE --expected-image-sha256 FROZEN_IMAGE_SHA256 \
  --output NEW_OUTPUT_DIR [--cache RETAINED_DOWNLOAD_CACHE] [--plan-only]

The input receipt must bind guest-dpkg-status, guest-packages.tsv and the separate
notice/support archive. All receipt hashes/sizes are checked before use. Production
transport is HTTPS snapshot.debian.org only, with no version search/substitution.
Snapshot's SHA1 locators are checked; .dsc identity and every Checksums-Sha256 entry
are checked separately. OpenPGP signatures are retained, NOT cryptographically
verified. This is acquisition/integrity evidence, not a legal certification.

Primary specifications checked November 12, 2026:
https://www.debian.org/doc/debian-policy/ch-controlfields.html
https://manpages.debian.org/trixie/dpkg-dev/deb-control.5.en.html
https://salsa.debian.org/snapshot-team/snapshot/-/blob/fec4bfc7a1d1ecbef411dca8677b6eb6f179d08b/API

Output source-index.json and SHA256SUMS accompany independent .tar assets, each
strictly smaller than 2 GiB. Partial acquisition writes explicit missing pairs,
exits nonzero and produces NO source archives; verified cached files are retained.
Already compressed source files are stored without another compression pass.
No source archive is unpacked and no source/build/install script is executed.
Inputs/cache must be owned and quiescent during acquisition/packaging.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request

ORIGIN = 'https://snapshot.debian.org'
MAX_ASSET = 2 ** 31 - 1
META_LIMIT = 8 * 1024 * 1024
NAME = r'[a-z0-9][a-z0-9+.-]+'
VERSION = r'[0-9][A-Za-z0-9.+:~\-]*'
REQUIRED_INPUTS = {'guest-dpkg-status', 'guest-packages.tsv', 'guest-distribution-support.tar.gz'}


class SourceError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise SourceError(message)


def basename(value):
    require(isinstance(value, str) and len(value) <= 1024 and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.~\-]*', value), 'unsafe artifact basename')
    require(value not in ('.', '..'), 'unsafe artifact basename')
    return value


def file_hash(path, algorithm='sha256'):
    digest = hashlib.new(algorithm)
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def regular(path):
    info = Path(path).lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'input/cache must be a regular, unlinked file: ' + str(path))
    return info


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode()


def verify_input(directory, expected_source, expected_image):
    directory = Path(directory)
    require(re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', expected_source or ''), 'independently supplied frozen source required')
    require(re.fullmatch(r'[0-9a-f]{64}', expected_image or ''), 'independently supplied frozen image SHA256 required')
    receipt_path = directory / 'distribution-input.json'
    require(regular(receipt_path).st_size <= META_LIMIT, 'receipt too large')
    receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
    require(receipt.get('schema') == 'keep.appliance.distribution-input/v1' and receipt.get('source') == expected_source
            and receipt.get('imageSha256') == expected_image, 'consumer receipt differs from frozen source/image')
    files = receipt.get('files')
    require(isinstance(files, list), 'consumer receipt has no files')
    seen = set()
    for record in files:
        require(isinstance(record, dict), 'invalid consumer file record')
        name = basename(record.get('file'))
        require(name not in seen, 'duplicate consumer file record')
        seen.add(name)
        require(isinstance(record.get('bytes'), int) and not isinstance(record['bytes'], bool) and record['bytes'] >= 0
                and re.fullmatch(r'[0-9a-f]{64}', record.get('sha256', '')), 'invalid consumer file size/hash')
        path = directory / name
        require(regular(path).st_size == record['bytes'] and file_hash(path) == record['sha256'], 'consumer artifact size/hash mismatch: ' + name)
    require(REQUIRED_INPUTS <= seen, 'consumer receipt omits required status/inventory/support artifacts')
    return receipt


def paragraphs(text):
    """Strict deb822 fields, preserving continuations and rejecting duplicate keys."""
    result, row, key = [], {}, None
    for line in text.splitlines() + ['']:
        if not line:
            if row:
                result.append(row)
            row, key = {}, None
        elif line[0] in ' \t':
            require(key is not None, 'orphan control continuation')
            row[key] += '\n' + line[1:]
        else:
            match = re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9-]*):[ \t]?(.*)', line)
            require(match is not None, 'malformed control line')
            key = match[1].lower()
            require(key not in row, 'duplicate control field: ' + key)
            row[key] = match[2]
    return result


def pair(name, version):
    require(re.fullmatch(NAME, name or '') and re.fullmatch(VERSION, version or ''), 'invalid exact source package/version')
    return name, version


def primary_source(row):
    source = row.get('source', '').strip()
    if not source:
        return pair(row['package'], row['version'])
    match = re.fullmatch(r'(' + NAME + r')(?:\s+\((' + VERSION + r')\))?', source)
    require(match is not None, 'invalid Source field')
    return pair(match[1], match[2] or row['version'])


def source_closure(status_text, inventory_text):
    records, binaries, skipped, closure = paragraphs(status_text), [], [], {}
    require(records, 'empty dpkg status')
    keys = set()
    for row in records:
        name = row.get('package', '')
        require(re.fullmatch(NAME, name), 'invalid dpkg Package field')
        state = row.get('status', '').split()
        require(len(state) == 3, 'missing/invalid dpkg Status for ' + name)
        if state[-1] == 'not-installed' and not row.get('version'):
            skipped.append({'package': name, 'status': row['status'], 'reason': 'not installed and no retained version'})
            continue
        version, architecture = row.get('version', ''), row.get('architecture', '')
        require(re.fullmatch(VERSION, version) and re.fullmatch(r'[a-z0-9][a-z0-9-]*', architecture), 'missing/invalid binary version/architecture for ' + name)
        identity = (name, version, architecture)
        require(identity not in keys, 'duplicate dpkg binary identity')
        keys.add(identity)
        source = primary_source(row)
        binary = {'package': name, 'version': version, 'architecture': architecture, 'status': row['status'],
                  'source': {'package': source[0], 'version': source[1]}, 'builtUsing': row.get('built-using', ''),
                  'staticBuiltUsing': row.get('static-built-using', '')}
        binaries.append(binary)
        closure.setdefault(source, []).append({'binary': name, 'version': version, 'architecture': architecture, 'field': 'Source'})
        for field in ('built-using', 'static-built-using'):
            raw = ' '.join(row.get(field, '').split())
            if not raw:
                continue
            for entry in raw.split(','):
                match = re.fullmatch(r'\s*(' + NAME + r')\s+\(=\s*(' + VERSION + r')\)\s*', entry)
                require(match is not None, 'non-exact/malformed ' + field + ' in ' + name)
                closure.setdefault(pair(match[1], match[2]), []).append({'binary': name, 'version': version, 'architecture': architecture, 'field': field})
    require(binaries, 'no versioned binary records')
    matched = set()
    for line in inventory_text.splitlines():
        if not line:
            continue
        cells = line.split('\t')
        require(len(cells) == 4, 'inventory must have four TSV columns')
        binary_name, version, source_name, source_version = cells
        name, colon, arch = binary_name.partition(':')
        if not version and any(item['package'] == name for item in skipped):
            continue
        choices = [b for b in binaries if b['package'] == name and b['version'] == version and (not colon or b['architecture'] == arch)]
        require(len(choices) == 1, 'inventory/status binary identity is absent or ambiguous: ' + binary_name)
        b = choices[0]
        require((source_name, source_version) == (b['source']['package'], b['source']['version']), 'inventory/status exact source mismatch: ' + binary_name)
        key = (name, version, b['architecture'])
        require(key not in matched, 'duplicate inventory binary')
        matched.add(key)
    require(matched == keys, 'inventory omits retained dpkg status binaries')
    return binaries, skipped, closure


def dsc_fields(data):
    text = data.decode('utf-8')
    signed = text.startswith('-----BEGIN PGP SIGNED MESSAGE-----\n') or text.startswith('-----BEGIN PGP SIGNED MESSAGE-----\r\n')
    text = text.replace('\r\n', '\n')
    if signed:
        header, separator, text = text.partition('\n\n')
        require(separator and re.search(r'^Hash: [A-Za-z0-9, -]+$', header, re.M), 'malformed clearsigned .dsc header')
        text, separator, signature = text.partition('\n-----BEGIN PGP SIGNATURE-----\n')
        require(separator and '-----END PGP SIGNATURE-----' in signature and not signature.split('-----END PGP SIGNATURE-----', 1)[1].strip(), 'malformed .dsc signature envelope')
        text = '\n'.join(line[2:] if line.startswith('- ') else line for line in text.split('\n'))
    rows = paragraphs(text)
    require(len(rows) == 1, '.dsc must contain one control stanza')
    return rows[0], signed


def dsc_members(fields):
    require('checksums-sha256' in fields, '.dsc lacks Checksums-Sha256')
    members = {}
    for line in fields['checksums-sha256'].splitlines():
        if not line.strip():
            continue
        cells = line.split()
        require(len(cells) == 3 and re.fullmatch(r'[0-9a-f]{64}', cells[0]) and re.fullmatch(r'[0-9]+', cells[1]), 'invalid .dsc SHA256 entry')
        name = basename(cells[2])
        require(name not in members and not name.endswith('.dsc'), 'duplicate/self-referencing .dsc member')
        members[name] = {'sha256': cells[0], 'bytes': int(cells[1])}
    require(members, '.dsc has empty source set')
    # Do not allow a file advertised by the other complete file tables to vanish
    # from SHA256 coverage (MD5/SHA1 themselves are not security admission).
    for field in ('files', 'checksums-sha1'):
        if field in fields:
            names = [basename(line.split()[-1]) for line in fields[field].splitlines() if line.strip()]
            require(len(names) == len(set(names)) and set(names) == set(members), '.dsc file tables disagree')
    return members


def official_url(url):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == 'https' and parsed.netloc == 'snapshot.debian.org' and not parsed.username and not parsed.password
            and not parsed.fragment and parsed.path.startswith(('/mr/package/', '/file/')), 'non-official snapshot URL refused')
    return url


class OfficialRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        official_url(newurl)
        return super().redirect_request(request, fp, code, message, headers, newurl)


class Snapshot:
    def __init__(self, cache, transport=None):
        self.cache = Path(cache)
        self.cache.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(self.cache.is_dir() and not self.cache.is_symlink(), 'download cache must be a real directory')
        self.transport = transport or urllib.request.build_opener(OfficialRedirect()).open

    def open(self, path):
        return self.transport(urllib.request.Request(official_url(ORIGIN + path), headers={'User-Agent': 'Keep-exact-source-companion/1'}), timeout=30)

    def metadata(self, package, version):
        path = '/mr/package/' + urllib.parse.quote(package, safe='') + '/' + urllib.parse.quote(version, safe='') + '/srcfiles?fileinfo=1'
        with self.open(path) as response:
            raw = response.read(META_LIMIT + 1)
        require(len(raw) <= META_LIMIT, 'snapshot metadata too large')
        value = json.loads(raw)
        require(value.get('package') == package and value.get('version') == version, 'snapshot returned another package/version')
        require(isinstance(value.get('result'), list) and value['result'] and isinstance(value.get('fileinfo'), dict), 'snapshot source metadata is incomplete')
        files = {}
        for item in value['result']:
            digest = item.get('hash') if isinstance(item, dict) else None
            require(re.fullmatch(r'[0-9a-f]{40}', digest or ''), 'invalid snapshot content locator')
            records = value['fileinfo'].get(digest)
            require(isinstance(records, list) and records, 'snapshot fileinfo missing')
            for record in records:
                require(isinstance(record, dict), 'invalid snapshot fileinfo record')
                name = basename(record.get('name'))
                size = record.get('size')
                require(isinstance(size, int) and not isinstance(size, bool) and size >= 0, 'invalid snapshot file size')
                previous = files.setdefault(name, {}).setdefault(digest, size)
                require(previous == size, 'snapshot file sizes conflict')
        return files, ORIGIN + path, hashlib.sha256(raw).hexdigest()

    def download(self, digest, size, sha256=None):
        require(isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{40}', digest) and isinstance(size, int) and not isinstance(size, bool) and size >= 0, 'invalid snapshot download identity')
        require(size <= MAX_ASSET, 'source file exceeds asset capacity')
        destination = self.cache / digest
        if destination.exists() or destination.is_symlink():
            require(regular(destination).st_size == size and file_hash(destination, 'sha1') == digest
                    and (sha256 is None or file_hash(destination) == sha256), 'retained cache differs from expected content')
            return destination
        fd, temporary = tempfile.mkstemp(prefix='partial-', dir=self.cache)
        first, second, actual = hashlib.sha1(), hashlib.sha256(), 0
        try:
            with os.fdopen(fd, 'wb') as output, self.open('/file/' + digest) as response:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    actual += len(chunk)
                    require(actual <= size, 'snapshot stream exceeds expected size')
                    first.update(chunk); second.update(chunk); output.write(chunk)
                output.flush(); os.fsync(output.fileno())
            require(actual == size and first.hexdigest() == digest and (sha256 is None or second.hexdigest() == sha256), 'snapshot file size/hash mismatch')
            os.replace(temporary, destination)
            return destination
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)  # Only this invocation's unconfirmed temporary file.

    def acquire(self, package, version):
        files, url, metadata_hash = self.metadata(package, version)
        dsc_name = basename(package + '_' + version.split(':')[-1] + '.dsc')
        require(dsc_name in files and len(files[dsc_name]) == 1, 'exact .dsc absent or ambiguous')
        digest, size = next(iter(files[dsc_name].items()))
        require(size <= META_LIMIT, '.dsc exceeds metadata capacity')
        dsc = self.download(digest, size)
        fields, signed = dsc_fields(dsc.read_bytes())
        require((fields.get('source'), fields.get('version')) == (package, version), '.dsc package/version differs from exact request')
        members = dsc_members(fields)
        records = [{'name': dsc_name, 'sha256': file_hash(dsc), 'snapshotSha1': digest, 'bytes': size, 'local': dsc}]
        for name, info in sorted(members.items()):
            require(name in files and len(files[name]) == 1, 'exact .dsc member absent or ambiguous in snapshot: ' + name)
            digest, size = next(iter(files[name].items()))
            require(size == info['bytes'], 'snapshot/.dsc member size mismatch: ' + name)
            path = self.download(digest, size, info['sha256'])
            records.append({'name': name, 'sha256': info['sha256'], 'snapshotSha1': digest, 'bytes': size, 'local': path})
        return {'package': package, 'version': version, 'metadataUrl': url, 'metadataSha256': metadata_hash,
                'dscSignedEnvelope': signed, 'openPgpSignatureVerified': False, 'files': records}


def tar_info(name, size):
    info = tarfile.TarInfo(name)
    info.size = size; info.mode = 0o644; info.mtime = 0; info.uid = info.gid = 0; info.uname = info.gname = ''
    return info


def tar_cost(name, size):
    return len(tar_info(name, size).tobuf(format=tarfile.PAX_FORMAT)) + ((size + 511) // 512) * 512


def tar_size(body_size):
    return ((body_size + 1024 + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE


def pack_sources(output, packages, max_asset=MAX_ASSET):
    """Independent deterministic tar assets, with each .dsc and its files in one package directory.

    Extract all assets into the same directory to reconstruct each complete .dsc
    set. Only validated regular files are written; source contents are never run.
    """
    require(isinstance(max_asset, int) and 10240 <= max_asset <= MAX_ASSET, 'asset cap must be 10240..2147483647 bytes')
    unique = {}
    for package in packages:
        pair(package['package'], package['version'])
        for record in package['files']:
            version_id = hashlib.sha256(package['version'].encode()).hexdigest()
            member = 'sources/' + package['package'] + '/' + version_id + '/' + basename(record['name'])
            record['member'] = member
            unique.setdefault(member, record)
    groups, current, size = [], [], 0
    for member, record in sorted(unique.items()):
        cost = tar_cost(member, record['bytes'])
        require(tar_size(cost) <= max_asset, 'one source file cannot fit a source asset: ' + record['name'])
        if current and tar_size(size + cost) > max_asset:
            groups.append(current); current, size = [], 0
        current.append((member, record)); size += cost
    if current:
        groups.append(current)
    assets = []
    for number, group in enumerate(groups, 1):
        name = 'debian-sources-' + str(number).zfill(4) + '.tar'
        destination = Path(output) / name
        with destination.open('xb') as stream, tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT) as archive:
            for member, record in group:
                path = record['local']
                require(regular(path).st_size == record['bytes'] and file_hash(path) == record['sha256'], 'source changed before packing')
                with path.open('rb') as source:
                    archive.addfile(tar_info(member, record['bytes']), source)
                record['asset'] = name
        require(destination.stat().st_size <= max_asset, 'source asset exceeded size cap')
        assets.append({'file': name, 'bytes': destination.stat().st_size, 'sha256': file_hash(destination)})
    for package in packages:
        for record in package['files']:
            record['asset'] = unique[record['member']]['asset']
    return assets


def build(input_dir, output, expected_source, expected_image, cache=None, plan_only=False, transport=None, max_asset=MAX_ASSET):
    require(not Path(output).exists() and not Path(output).is_symlink(), 'output already exists; preserve it and use a new output with the retained cache')
    require(isinstance(max_asset, int) and 10240 <= max_asset <= MAX_ASSET, 'invalid source asset cap')
    receipt = verify_input(input_dir, expected_source, expected_image)
    input_dir, output = Path(input_dir), Path(output)
    metadata = {}
    for name in ('guest-dpkg-status', 'guest-packages.tsv'):
        record = next(row for row in receipt['files'] if row['file'] == name)
        require(record['bytes'] <= META_LIMIT, 'consumer metadata too large: ' + name)
        data = (input_dir / name).read_bytes()
        require(len(data) == record['bytes'] and hashlib.sha256(data).hexdigest() == record['sha256'], 'consumer metadata changed before parsing')
        metadata[name] = data
    receipt_bytes = (input_dir / 'distribution-input.json').read_bytes()
    require(json.loads(receipt_bytes) == receipt, 'consumer receipt changed before acquisition')
    support = 'guest-distribution-support.tar.gz'
    support_record = next(row for row in receipt['files'] if row['file'] == support)
    require(support_record['bytes'] <= max_asset, 'notice/support archive exceeds asset cap')
    binaries, skipped, closure = source_closure(metadata['guest-dpkg-status'].decode('utf-8'), metadata['guest-packages.tsv'].decode('utf-8'))
    output.mkdir(mode=0o700)  # Never replace an older result or follow an output symlink.
    index = {'schema': 'keep.appliance.debian-source-companion/v1', 'source': expected_source, 'imageSha256': expected_image,
             'runtimeSource': receipt.get('runtimeSource', receipt['source']),
             'generatorScriptSha256': file_hash(Path(__file__)),
             'consumerReceiptSha256': hashlib.sha256(receipt_bytes).hexdigest(), 'consumerArtifacts': receipt['files'],
             'scope': 'All retained versioned dpkg-status Source, Built-Using and Static-Built-Using pairs; no Build-Depends expansion',
             'trust': 'HTTPS official snapshot metadata, checked SHA1 locators and .dsc SHA256 contents; no OpenPGP verification',
             'use': 'Extract all listed source .tar assets into the same directory. Each sources/package/version-hash directory contains an exact .dsc and its original-basename files. Keep source-index.json, SHA256SUMS and the separate consumer notice/support asset adjacent.',
             'binaries': binaries, 'skipped': skipped, 'required': [{'package': p, 'version': v, 'requiredBy': refs} for (p, v), refs in sorted(closure.items())],
             'packages': [], 'missing': [], 'assets': [], 'complete': False, 'planOnly': plan_only}
    if not plan_only:
        snapshot = Snapshot(cache or output / 'cache', transport)
        for package, version in sorted(closure):
            try:
                acquired = snapshot.acquire(package, version)
                acquired['requiredBy'] = closure[(package, version)]
                index['packages'].append(acquired)
            except (SourceError, OSError, ValueError, KeyError, TypeError, urllib.error.URLError) as error:
                index['missing'].append({'package': package, 'version': version, 'reason': str(error), 'requiredBy': closure[(package, version)]})
        if not index['missing']:
            try:
                index['assets'] = pack_sources(output, index['packages'], max_asset)
                index['complete'] = True
            except (SourceError, OSError) as error:
                index['missing'].append({'package': None, 'version': None, 'reason': 'source archive incomplete: ' + str(error)})
    for package in index['packages']:
        for record in package['files']:
            record.pop('local', None)
    (output / 'distribution-input.json').write_bytes(receipt_bytes)
    for name, data in metadata.items():
        (output / name).write_bytes(data)
    with (input_dir / support).open('rb') as source, (output / support).open('xb') as destination:
        shutil.copyfileobj(source, destination, length=1024 * 1024)
        destination.flush(); os.fsync(destination.fileno())
    require(regular(output / support).st_size == support_record['bytes'] and file_hash(output / support) == support_record['sha256'], 'notice/support archive changed during copy')
    (output / 'source-index.json').write_bytes(json_bytes(index))
    names = ['source-index.json', 'distribution-input.json', 'guest-dpkg-status', 'guest-packages.tsv', 'guest-distribution-support.tar.gz'] + [a['file'] for a in index['assets']]
    require(all((output / name).stat().st_size <= max_asset for name in names), 'output metadata exceeds asset cap')
    (output / 'SHA256SUMS').write_text(''.join(file_hash(output / name) + '  ' + name + '\n' for name in names), encoding='ascii')
    return index


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expected-source', required=True)
    parser.add_argument('--expected-image-sha256', required=True)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--plan-only', action='store_true', help='verify consumer input and emit exact required pairs without network/source acquisition')
    parser.add_argument('--max-asset-bytes', type=int, default=MAX_ASSET)
    args = parser.parse_args()
    try:
        result = build(args.input, args.output, args.expected_source, args.expected_image_sha256,
                       args.cache, args.plan_only, max_asset=args.max_asset_bytes)
        print(json.dumps({'complete': result['complete'], 'planOnly': result['planOnly'], 'requiredPairs': len(result['required']),
                          'acquiredPairs': len(result['packages']), 'missingPairs': len(result['missing']), 'assets': result['assets']}))
        return 0 if result['complete'] or args.plan_only else 1
    except (SourceError, OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, 'Source companion refused: ' + str(error) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
