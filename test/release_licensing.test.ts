import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

const source = process.cwd();
const tool = join(source, "tools/release_notices.mjs");
const staticRuntimeNotices = [
  "musl-1.2.5-COPYRIGHT.txt",
  "compiler-builtins-LICENSE.txt",
  "libm-LICENSE.txt",
  "compiler-rt-LICENSE.txt",
  "compiler-rt-CREDITS.txt",
  "libunwind-LICENSE.txt",
];
const sha = (value: string) => createHash("sha256").update(value).digest("hex");
function write(root: string, path: string, value: string) {
  mkdirSync(dirname(join(root, path)), { recursive: true });
  writeFileSync(join(root, path), value);
}
function cargo(root: string, dir: string, name: string, notice = "Fixture copyright and permission.\n") {
  write(root, `${dir}/Cargo.toml`, `[package]\nname = "${name}"\nversion = "1.0.0"\nlicense = "MIT"\n\n[dependencies]\n`);
  write(root, `${dir}/LICENSE`, notice);
  write(root, `${dir}/.cargo-checksum.json`, JSON.stringify({ package: "a".repeat(64), files: { LICENSE: sha(notice) } }));
}
function fixture() {
  const root = mkdtempSync(join(tmpdir(), "keep-notices-test-"));
  write(root, "native/toolchain-lock.json", JSON.stringify({ toolchain: "1.97.1-x86_64-unknown-linux-gnu" }));
  write(root, "native/licenses/rust-1.97.1-COPYRIGHT-library.html", readFileSync(join(source, "native/licenses/rust-1.97.1-COPYRIGHT-library.html"), "utf8"));
  for (const name of staticRuntimeNotices)
    write(root, `native/licenses/${name}`, readFileSync(join(source, "native/licenses", name), "utf8"));
  cargo(root, "native/vendor-p2/example", "example");
  cargo(root, "native/vendor-transport/transport", "transport");
  const pkg = { name: "typescript", version: "5.9.3", license: "Apache-2.0" };
  write(root, "node_modules/typescript/package.json", JSON.stringify(pkg));
  write(root, "node_modules/typescript/LICENSE.txt", "Fixture license.\r\n");
  write(root, "node_modules/typescript/ThirdPartyNoticeText.txt", "Embedded fixture attribution.\n");
  const deps = { dependencies: { typescript: "5.9.3" } };
  write(root, "package.json", JSON.stringify(deps));
  write(root, "package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: {
    "": deps,
    "node_modules/typescript": { ...pkg, resolved: "https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz", integrity: "sha512-YQ==" },
  } }));
  return root;
}
function run(root: string, check = false) {
  return spawnSync(process.execPath, [tool, "--root", root, ...(check ? ["--check"] : [])], {
    encoding: "utf8", timeout: 15000, maxBuffer: 2 * 1024 * 1024,
    env: { PATH: "/usr/bin:/bin", LANG: "C" },
  });
}
function withFixture(body: (root: string) => void) {
  const root = fixture();
  try { body(root); } finally { rmSync(root, { recursive: true, force: true }); }
}
function retain(root: string) {
  const result = run(root);
  assert.equal(result.status, 0, result.stderr);
  write(root, "THIRD_PARTY_NOTICES.txt", result.stdout);
  return result.stdout;
}

test("retained source attribution matches all current vendor and locked npm notice inputs", () => {
  const result = run(source, true);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Not redistribution clearance/);
  const bundle = readFileSync(join(source, "THIRD_PARTY_NOTICES.txt"), "utf8");
  assert.match(bundle, /\(MIT OR Apache-2\.0\) AND Unicode-3\.0/);
  assert.match(bundle, /typescript\/ThirdPartyNoticeText\.txt/);
  assert.match(bundle, /cfg_aliases-0\.2\.2\/NOTICES\.md/);
});

test("notice rendering is deterministic, includes nested texts, and normalizes display only", () => withFixture(root => {
  write(root, "node_modules/typescript/nested/COPYRIGHT.txt", "Nested holder.\r\n");
  const output = retain(root);
  assert.equal(output, run(root).stdout);
  assert.equal(run(root, true).status, 0);
  assert.match(output, /Nested holder/);
  assert.match(output, /Embedded fixture attribution/);
  assert.ok(output.includes(sha("Fixture license.\r\n")), "digest describes original CRLF bytes");
  assert.ok(!output.includes("\r"));
}));

test("changed, added and removed notice inputs cannot reuse a stale passing bundle", () => {
  for (const mutate of [
    (root: string) => cargo(root, "native/vendor-p2/example", "example", "Corrected copyright.\n"),
    (root: string) => write(root, "node_modules/typescript/NOTICE", "New obligation.\n"),
    (root: string) => rmSync(join(root, "node_modules/typescript/ThirdPartyNoticeText.txt")),
    (root: string) => cargo(root, "native/vendor-p2/new-component", "new-component"),
  ]) withFixture(root => {
    retain(root); mutate(root);
    const result = run(root, true);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /bundle is stale/);
  });
});

test("missing required notice or changed vendor notice checksum fails before generation", () => {
  for (const mutate of [
    (root: string) => rmSync(join(root, "native/vendor-p2/example/LICENSE")),
    (root: string) => write(root, "native/vendor-p2/example/LICENSE", "Unrecorded change.\n"),
  ]) withFixture(root => {
    mutate(root); const result = run(root);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /no notice files|local notice checksum mismatch/);
  });
});

test("mismatched npm identity and lockfile root are rejected", () => {
  for (const mutate of [
    (root: string) => write(root, "node_modules/typescript/package.json", JSON.stringify({ name: "typescript", version: "5.9.2", license: "Apache-2.0" })),
    (root: string) => write(root, "package.json", JSON.stringify({ dependencies: { typescript: "*" } })),
  ]) withFixture(root => {
    mutate(root); const result = run(root);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /differ.*lockfile/);
  });
});

test("unsupported Cargo metadata and escaping license paths fail closed", () => {
  for (const tail of ['license = ""', 'license = ["MIT"]', 'license-file = "../../outside/LICENSE"']) withFixture(root => {
    write(root, "native/vendor-p2/example/Cargo.toml", `[package]\nname = "example"\nversion = "1.0.0"\n${tail}\n`);
    assert.notEqual(run(root).status, 0);
  });
});

test("symlinks in a component or an npm package ancestor are refused", () => {
  for (const mutate of [
    (root: string) => symlinkSync("LICENSE", join(root, "native/vendor-p2/example/NOTICE")),
    (root: string) => { rmSync(join(root, "node_modules/typescript"), { recursive: true }); symlinkSync(join(source, "node_modules/typescript"), join(root, "node_modules/typescript")); },
  ]) withFixture(root => {
    mutate(root); const result = run(root);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /symlink refused/);
  });
});

test("toolchain change or changed/missing Rust notice prevents a passing notice check", () => {
  for (const mutate of [
    (root: string) => write(root, "native/toolchain-lock.json", JSON.stringify({ toolchain: "another-toolchain" })),
    (root: string) => write(root, "native/licenses/rust-1.97.1-COPYRIGHT-library.html", "altered notice"),
    (root: string) => rmSync(join(root, "native/licenses/rust-1.97.1-COPYRIGHT-library.html")),
  ]) withFixture(root => {
    retain(root); mutate(root);
    assert.notEqual(run(root, true).status, 0);
  });
});

test("every static-runtime notice is required unchanged for a passing notice check", () => {
  for (const name of staticRuntimeNotices) withFixture(root => {
    retain(root);
    write(root, `native/licenses/${name}`, "altered attribution");
    assert.notEqual(run(root, true).status, 0, `changed ${name} must fail`);
    rmSync(join(root, "native/licenses", name));
    assert.notEqual(run(root, true).status, 0, `missing ${name} must fail`);
  });
});

test("source install is separate from pack-time build and attribution reaches the package whitelist", () => {
  const pkg = JSON.parse(readFileSync(join(source, "package.json"), "utf8"));
  const lock = JSON.parse(readFileSync(join(source, "package-lock.json"), "utf8"));
  for (const name of ["prepare", "preinstall", "install", "postinstall"]) assert.equal(pkg.scripts[name], undefined);
  assert.equal(pkg.scripts.prepack, "npm run test:notices && npm run build");
  for (const path of ["NOTICE", "THIRD_PARTY_NOTICES.txt", "docs/licensing.md", "native/toolchain-inventory.json", "native/licenses/README.md", "native/licenses/rust-1.97.1-COPYRIGHT-library.html"])
    assert.ok(pkg.files.includes(path), `missing package attribution/build input: ${path}`);
  for (const name of staticRuntimeNotices)
    assert.ok(pkg.files.includes(`native/licenses/${name}`), `missing runtime notice: ${name}`);
  for (const section of ["dependencies", "devDependencies"]) assert.deepEqual(pkg[section], lock.packages[""][section]);
  assert.equal(pkg.dependencies.typescript, lock.packages["node_modules/typescript"].version);
  assert.equal(pkg.devDependencies["@types/node"], lock.packages["node_modules/@types/node"].version);
});
