/** Offline path-binding regression: no child launch, namespace, service or VM. */
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, realpathSync, rmSync, symlinkSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import test from 'node:test';
import { sampleNodeToolchain } from './reviewer_node_toolchain.mjs';

test('canonical selected executable determines matching bin and jail root across versions and symlinks', () => {
  const temporary = mkdtempSync(join(tmpdir(), 'sample node binding '));
  try {
    for (const version of ['22.23.4', '22.23.5']) {
      const root = join(temporary, `node-v${version}-linux-x64`), bin = join(root, 'bin'), executable = join(bin, 'node');
      mkdirSync(bin, { recursive: true });
      writeFileSync(executable, `unexecuted version ${version} fixture`);
      const alias = join(temporary, `selected-${version}`);
      symlinkSync(executable, alias);
      for (const selected of [executable, alias]) {
        const actual = sampleNodeToolchain(selected);
        assert.deepEqual(actual, { executable, bin, root });
        assert.equal(join(actual.root, 'bin', 'node'), actual.executable);
        assert.equal(join(actual.bin, 'node'), actual.executable);
      }
    }
  } finally { rmSync(temporary, { recursive: true, force: true }); }
});

test('default binding selects the actual running Node, not a versioned constant', () => {
  const executable = realpathSync(process.execPath), actual = sampleNodeToolchain();
  assert.deepEqual(actual, { executable, bin: dirname(executable), root: dirname(dirname(executable)) });
  const launcher = readFileSync(new URL('./reviewer_local_sample.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(launcher, /node-v\d/);
});

test('missing selected executable refuses instead of choosing an ambient toolchain', () => {
  const temporary = mkdtempSync(join(tmpdir(), 'sample missing node '));
  try {
    assert.throws(() => sampleNodeToolchain(join(temporary, 'absent-node')), { code: 'ENOENT' });
  } finally { rmSync(temporary, { recursive: true, force: true }); }
});
