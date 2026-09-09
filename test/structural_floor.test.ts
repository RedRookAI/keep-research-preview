import { test } from "node:test";
import assert from "node:assert/strict";

import {
  structuralFloor,
  defaultFloorPolicy,
  type OpDescription,
  type FloorPolicy,
} from "../src/floor/structural_floor.js";

// Build Step 2 — the structural floor (in-TCB decidable predicates). These prove the
// floor auto-executes ONLY the narrow reversible class and fail-safe GATES everything
// else, including everything UNKNOWN. Verify by disproof.

const policy: FloorPolicy = defaultFloorPolicy("/work/repo");

// A fully reversible op: in-workspace file edit, bounded write-set, has an inverse,
// no external sink, not catastrophic, not protected.
const reversibleOp: OpDescription = {
  kind: "file.edit",
  writeSet: ["src/app.ts"],
  hasInverse: true,
  raw: "const a = 2;",
};

test("FLOOR: a fully-reversible in-workspace edit is reversible-execute", () => {
  const v = structuralFloor(reversibleOp, policy);
  assert.equal(v.verdict, "reversible-execute");
});

test("FLOOR: an external sink gates (git push / network / DELETE-no-WHERE)", () => {
  for (const raw of ["git push origin main", "curl https://evil.example", "DELETE FROM users"]) {
    const v = structuralFloor({ ...reversibleOp, raw }, policy);
    assert.equal(v.verdict, "gate", `should gate: ${raw}`);
    assert.ok(v.reasons.includes("external-sink"));
  }
});

test("FLOOR: a catastrophic op gates (rm -rf /, mkfs, dd of=/dev)", () => {
  for (const raw of ["rm -rf /", "mkfs.ext4 /dev/sda", "dd if=/dev/zero of=/dev/sda"]) {
    const v = structuralFloor({ ...reversibleOp, raw }, policy);
    assert.equal(v.verdict, "gate", `should gate: ${raw}`);
    assert.ok(v.reasons.includes("catastrophic-op"));
  }
});

test("FLOOR: touching a protected resource gates (.git, .env, secrets, spine, backups)", () => {
  for (const p of [".git/config", ".env", "secrets/key.pem", "spine/chain.jsonl", "backups/db.sql"]) {
    const v = structuralFloor({ ...reversibleOp, writeSet: [p] }, policy);
    assert.equal(v.verdict, "gate", `should gate write to: ${p}`);
    assert.ok(v.reasons.includes("protected-resource"));
  }
});

test("FLOOR: an UNKNOWN (undefined) write-set fails safe → gate (unbounded)", () => {
  const v = structuralFloor({ kind: "file.edit", hasInverse: true }, policy); // no writeSet
  assert.equal(v.verdict, "gate");
  assert.ok(v.reasons.includes("write-set-unbounded-or-escapes-jail"));
});

test("FLOOR: a write-set escaping the jail (.. or absolute) gates", () => {
  for (const p of ["../etc/passwd", "src/../../secret", "/etc/hosts"]) {
    const v = structuralFloor({ ...reversibleOp, writeSet: [p] }, policy);
    assert.equal(v.verdict, "gate", `should gate escape: ${p}`);
  }
});

test("FLOOR: an UNKNOWN inverse (undefined hasInverse) fails safe → gate", () => {
  const v = structuralFloor({ kind: "file.edit", writeSet: ["src/a.ts"] }, policy); // no hasInverse
  assert.equal(v.verdict, "gate");
  assert.ok(v.reasons.includes("no-constructible-inverse"));
});

test("FLOOR: an op-kind NOT on the reversible whitelist gates (default-deny by kind)", () => {
  const v = structuralFloor(
    { kind: "shell", writeSet: ["src/a.ts"], hasInverse: true },
    policy,
  );
  assert.equal(v.verdict, "gate");
  assert.ok(v.reasons.some((r) => r.startsWith("kind-not-on-reversible-whitelist")));
});

test("FLOOR: is pure + model-independent — deterministic on frozen input, no I/O", () => {
  const frozen = Object.freeze({ ...reversibleOp });
  const a = structuralFloor(frozen, policy);
  const b = structuralFloor(frozen, policy);
  assert.deepEqual(a, b, "same input ⇒ same output");
  // there is no model parameter to consult — the signature itself guarantees it.
});
