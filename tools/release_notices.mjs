#!/usr/bin/env node
// Local attribution inventory, not redistribution clearance or a binary-linkage SBOM.
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
let root = resolve(fileURLToPath(new URL('..', import.meta.url)));
let check = false;
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--check' && !check) check = true;
  else if (args[i] === '--root' && i === 0 && args[i + 1]) root = resolve(args[++i]);
  else throw Error('usage: node tools/release_notices.mjs [--root SOURCE] [--check]');
}
root = realpathSync(root);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const posix = path => path.split(sep).join('/');
function local(path) {
  if (!path || isAbsolute(path) || path.includes('\\') || path.split('/').some(p => !p || p === '.' || p === '..'))
    throw Error(`unsafe inventory path: ${path}`);
  let full = root;
  for (const part of path.split('/')) {
    full = join(full, part);
    if (lstatSync(full).isSymbolicLink()) throw Error(`symlink refused: ${path}`);
  }
  return full;
}
function bytes(path) {
  const full = local(path), stat = lstatSync(full);
  if (!stat.isFile() || stat.size > 2 * 1024 * 1024) throw Error(`not a bounded regular input: ${path}`);
  return readFileSync(full);
}
const text = path => new TextDecoder('utf-8', { fatal: true }).decode(bytes(path));
const json = path => JSON.parse(text(path));
// The Rust standard library is supplied by the toolchain, outside Cargo/npm locks.
// Preserve its upstream report separately instead of pretending it is a Cargo crate.
if (json('native/toolchain-lock.json').toolchain !== '1.97.1-x86_64-unknown-linux-gnu')
  throw Error('toolchain runtime attribution needs review for changed Rust version');
if (digest(bytes('native/licenses/rust-1.97.1-COPYRIGHT-library.html')) !==
    '968db7452f5df771f045063a28073bf1b93b3f51d8a792e2c2af7e9eecf11205')
  throw Error('retained Rust standard-library notice differs from reviewed input');
// Pinned release-source notices for the static runtime inputs are separate from
// the Cargo/npm inventory. Hashes detect accidental omission/drift, not ownership.
for (const [name, expected] of [
  ['musl-1.2.5-COPYRIGHT.txt', 'f9bc4423732350eb0b3f7ed7e91d530298476f8fec0c6c427a1c04ade22655af'],
  ['compiler-builtins-LICENSE.txt', 'ab6eec6caf0fa5775e411c7a8bc6a45c4ef2956b0980b157ab74fc5cd62a928b'],
  ['libm-LICENSE.txt', '3823dda7cf046602f4b4e77ec8e227863dc4736037cc85bb33d9f19febe16bb7'],
  ['compiler-rt-LICENSE.txt', '1a8f1058753f1ba890de984e48f0242a3a5c29a6a8f2ed9fd813f36985387e8d'],
  ['compiler-rt-CREDITS.txt', 'a9901f47a089da41e4690682d00ce4cedaa2baf41fedbe79beee366d43ac2461'],
  ['libunwind-LICENSE.txt', 'b5efebcaca80879234098e52d1725e6d9eb8fb96a19fce625d39184b705f7b6d'],
]) {
  if (digest(bytes(`native/licenses/${name}`)) !== expected)
    throw Error(`retained static-runtime notice differs from reviewed input: ${name}`);
}
function field(value, label) {
  if (typeof value !== 'string' || !value.trim() || /[\x00-\x1f\x7f]/u.test(value))
    throw Error(`missing or unsupported ${label}`);
  return value;
}
const noticeName = /^(?:(?:licen[cs]e|notices?|copyright)(?:$|[._-])|third[-_]?party.*(?:notice|licen[cs]e))/iu;
function notices(directory, additional = []) {
  const found = new Set(additional);
  function walk(path) {
    for (const name of readdirSync(local(path)).sort()) {
      const child = `${path}/${name}`, stat = lstatSync(local(child));
      if (stat.isDirectory()) walk(child);
      else if (!stat.isFile()) throw Error(`special input refused: ${child}`);
      else if (noticeName.test(name)) found.add(child);
    }
  }
  walk(directory);
  if (!found.size) throw Error(`no notice files: ${directory}`);
  return [...found].sort().map(path => ({ path, content: text(path).replace(/\r\n/gu, '\n'), sha256: digest(bytes(path)) }));
}
function cargoPackage(path) {
  const input = text(path);
  const section = input.match(/^\[package\]\s*\n([\s\S]*?)(?=^\[|$(?![\s\S]))/mu)?.[1];
  if (!section) throw Error(`missing normalized Cargo package section: ${path}`);
  const values = {};
  for (const line of section.split('\n')) {
    const row = line.match(/^(name|version|license|license-file)\s*=\s*(.*)$/u);
    if (!row) continue;
    if (Object.hasOwn(values, row[1])) throw Error(`duplicate Cargo declaration: ${path}:${row[1]}`);
    // Existing cargo-vendor manifests use one JSON-compatible quoted string here.
    // Do not guess when a future manifest uses another TOML representation.
    values[row[1]] = field(JSON.parse(row[2]), `Cargo ${row[1]} in ${path}`);
  }
  field(values.name, `Cargo name in ${path}`);
  field(values.version, `Cargo version in ${path}`);
  if (!values.license && !values['license-file']) throw Error(`missing Cargo license: ${path}`);
  if (!/^[a-zA-Z0-9_-]+$/u.test(values.name) || !/^[0-9A-Za-z.+-]+$/u.test(values.version))
    throw Error(`unsupported Cargo identity: ${path}`);
  return values;
}

const components = [];
for (const vendor of ['native/vendor-p2', 'native/vendor-transport']) {
  for (const name of readdirSync(local(vendor)).sort()) {
    const dir = `${vendor}/${name}`;
    if (!lstatSync(local(dir)).isDirectory()) throw Error(`unexpected vendor-root entry: ${dir}`);
    const declared = cargoPackage(`${dir}/Cargo.toml`);
    const checksum = json(`${dir}/.cargo-checksum.json`);
    if (!/^[a-f0-9]{64}$/u.test(checksum.package) || !checksum.files || typeof checksum.files !== 'object')
      throw Error(`missing Cargo checksum identity: ${dir}`);
    const extra = declared['license-file'] ? [`${dir}/${declared['license-file']}`] : [];
    const included = notices(dir, extra);
    for (const notice of included) {
      const key = posix(relative(local(dir), local(notice.path)));
      if (checksum.files[key] !== notice.sha256) throw Error(`local notice checksum mismatch: ${notice.path}`);
    }
    components.push({ id: `${declared.name}@${declared.version}`, location: dir,
      declared: declared.license ?? `license-file: ${declared['license-file']}`,
      origin: `https://crates.io/api/v1/crates/${declared.name}/${declared.version}/download`,
      identity: `Locally recorded archive SHA-256: ${checksum.package}`,
      notices: included });
  }
}
const lock = json('package-lock.json'), manifest = json('package.json');
if (lock.lockfileVersion !== 3 || !lock.packages?.['']) throw Error('unsupported npm lockfile');
for (const section of ['dependencies', 'devDependencies']) {
  if (JSON.stringify(manifest[section] ?? {}) !== JSON.stringify(lock.packages[''][section] ?? {}))
    throw Error(`root npm ${section} differ from lockfile`);
}
for (const [path, entry] of Object.entries(lock.packages).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) {
  if (path === '') continue;
  if (!/^node_modules\/(?:@[^/]+\/)?[^/]+$/u.test(path)) throw Error(`unsupported npm package location: ${path}`);
  const installed = json(`${path}/package.json`);
  if (installed.name !== path.slice('node_modules/'.length) || installed.version !== entry.version || installed.license !== entry.license)
    throw Error(`installed npm identity/license differs from lockfile: ${path}`);
  field(entry.version, `npm version: ${path}`);
  field(entry.license, `npm license: ${path}`);
  if (typeof entry.resolved !== 'string' || !entry.resolved.startsWith('https://registry.npmjs.org/') ||
      typeof entry.integrity !== 'string' || !/^sha512-[A-Za-z0-9+/]+={0,2}$/u.test(entry.integrity))
    throw Error(`unsupported npm registry identity: ${path}`);
  components.push({ id: `${installed.name}@${entry.version}`, location: path,
    declared: entry.license, origin: entry.resolved, identity: `Lockfile archive integrity: ${entry.integrity}`,
    notices: notices(path) });
}
const parts = [
  'Keep — third-party attribution inventory\n',
  'Generated from local vendored source and locked, installed npm dependencies.\n',
  'Includes all vendored packages (not just linked code) and runtime/development npm packages.\n',
  'Registry locators and local digests are not verified provenance or redistribution clearance.\n',
  'License expressions below are upstream declarations, not independently validated SPDX expressions.\n',
  'All discovered notice alternatives are retained; see NOTICE and docs/licensing.md.\n',
];
for (const item of components) {
  parts.push(`\n===== ${item.id} =====\nLocation: ${item.location}\nDeclared license: ${item.declared}\nRegistry locator: ${item.origin}\n${item.identity}\n`);
  for (const notice of item.notices)
    parts.push(`\n----- ${notice.path} | SHA-256 ${notice.sha256} -----\n${notice.content}\n`);
}
// Portable display text uses LF and a single final newline; hashes bind raw inputs.
const output = `${parts.join('').trimEnd()}\n`;
if (check) {
  if (text('THIRD_PARTY_NOTICES.txt') !== output) throw Error('third-party notice bundle is stale; regenerate and review it');
  console.log(`Local attribution inventory matches: ${components.length} package locations, ${components.reduce((n, c) => n + c.notices.length, 0)} notice files; separate Rust library and static-runtime notices match. Not redistribution clearance.`);
} else process.stdout.write(output);
