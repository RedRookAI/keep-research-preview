#!/usr/bin/env node
/** Independent-process file/predicate measurer for A4. The compiler verifies every returned fact itself. */
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { isAbsolute, join, relative, sep } from "node:path";
const fail = (reason) => { process.stderr.write(`A4-PROBE-REFUSED:${reason}\n`); process.exit(2); };
let request; try { request = JSON.parse(Buffer.from(process.argv[2] ?? "", "base64url").toString("utf8")); } catch { fail("request-json"); }
if (request === null || typeof request !== "object" || Array.isArray(request) || Object.keys(request).sort().join(",") !== "checks,nonce,propositionDigest" || !/^[0-9a-f]{32}$/.test(request.nonce ?? "") || !/^[0-9a-f]{64}$/.test(request.propositionDigest ?? "") || !Array.isArray(request.checks) || request.checks.length > 128) fail("request-shape");
const root = realpathSync(process.cwd()); const facts = [];
for (const [index, check] of request.checks.entries()) {
  if (check === null || typeof check !== "object" || Array.isArray(check) || Object.keys(check).sort().join(",") !== (check.kind === "contains" ? "kind,needle,path" : "kind,path") || (check.kind !== "file" && check.kind !== "contains") || typeof check.path !== "string" || (check.kind === "contains" && typeof check.needle !== "string")) fail(`check-${index}`);
  let path; try { path = realpathSync(join(root, ...check.path.split("/"))); const rel = relative(root, path); if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel) || !lstatSync(path).isFile()) fail(`path-${index}`); } catch { fail(`path-${index}`); }
  const bytes = readFileSync(path); facts.push({ kind: check.kind, path: check.path, digest: createHash("sha256").update(bytes).digest("hex"), matched: check.kind === "file" || bytes.toString("utf8").includes(check.needle) });
}
process.stdout.write(JSON.stringify({ sentinel: "KEEP-CAPABILITY-EVIDENCE-V2", nonce: request.nonce, propositionDigest: request.propositionDigest, facts }));
