#!/usr/bin/env node
/**
 * witness_verify.mjs — the STANDALONE, THIRD-PARTY witness verifier (Mechanical-Enforcement Increment 12b). [netguard-allow]
 *
 * The property that makes a tamper-evident log REAL is that someone OTHER THAN THE PRODUCER re-derives its root against
 * a reference they hold. This tool is that someone. It re-walks a sealed chain and — crucially — checks it against a
 * CALLER-SUPPLIED EXTERNAL REFERENCE (a ChainWitness the producer exported OUT of its own write-set). It CANNOT itself
 * establish custody or independence of that reference — that the reference is genuinely beyond the producer's reach (a
 * separate principal / append-only receiver / quorum) is the OPERATOR'S PRECONDITION. Its exit codes make the honest
 * distinction the whole increment turns on:
 *
 *   exit 0  VERIFIED   — the chain is internally valid AND reaches the highest supplied external root with a matching
 *                        cumulative root. A real verification, TO THE EXTENT the supplied reference is trustworthy.
 *   exit 3  UNVERIFIED — internally consistent, but NO external reference was supplied. This is NOT a verification: it
 *                        only says "the producer's disk is self-consistent", which a compromised producer can forge.
 *   exit 1  TAMPER     — internal chain invalid, or it FORKED from the exported root (different history at that seq).
 *   exit 2  ROLLBACK   — the chain no longer reaches the highest exported seq: it was truncated / rolled back below the
 *                        exported high-water-mark.
 *   exit 4  USAGE/IO   — bad arguments or unreadable input.
 *
 * It is a THIN CLI over the SAME compiled verification primitive the monitor uses in-process (classifyChain in
 * src/witness/witness_export.ts) — so the standalone check can never drift from the built-in one. Requires `npm run
 * build` first (it imports from dist/). Zero third-party deps.
 *
 * Usage:  node tools/witness_verify.mjs --chain <chain.jsonl> [--root <exported-root.jsonl>]
 */
import { readFileSync } from "node:fs";

function flag(name) { const i = process.argv.indexOf(name); return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : undefined; }
function readJsonl(path) {
  const out = [];
  for (const line of readFileSync(path, "utf8").split("\n")) { const t = line.trim(); if (t.length > 0) out.push(JSON.parse(t)); }
  return out;
}

const chainPath = flag("--chain");
const rootPath = flag("--root");
if (!chainPath) { console.error("usage: witness_verify.mjs --chain <chain.jsonl> [--root <exported-root.jsonl>]"); process.exit(4); }

let classifyChain;
try { ({ classifyChain } = await import(new URL("../dist/src/witness/witness_export.js", import.meta.url))); }
catch (e) { console.error(`[witness-verify] cannot load the compiled verifier (run \`npm run build\` first): ${e?.message ?? e}`); process.exit(4); }

let blocks, roots;
try { blocks = readJsonl(chainPath); } catch (e) { console.error(`[witness-verify] cannot read chain ${chainPath}: ${e?.message ?? e}`); process.exit(4); }
try { roots = rootPath ? readJsonl(rootPath) : undefined; } catch (e) { console.error(`[witness-verify] cannot read root ${rootPath}: ${e?.message ?? e}`); process.exit(4); }

const outcome = classifyChain(blocks, roots);
switch (outcome.kind) {
  case "verified":
    console.log(`[witness-verify] VERIFIED — chain is internally valid and matches the caller-supplied external reference at seq ${outcome.seq} (independence of that reference is the operator's precondition).`);
    process.exit(0);
  case "internally-consistent":
    console.error(rootPath
      ? `[witness-verify] UNVERIFIED — the chain is internally consistent, but the supplied --root (${rootPath}) contained no valid exported root. This is NOT a verification.`
      : `[witness-verify] UNVERIFIED — the chain is internally consistent, but NO external reference was supplied (--root). This is NOT a verification: a compromised producer can forge a self-consistent chain. Supply an out-of-write-set exported root.`);
    process.exit(3);
  case "rollback":
    console.error(`[witness-verify] ROLLBACK — ${outcome.reason}. The chain was truncated/rolled back below the exported high-water-mark.`);
    process.exit(2);
  case "tamper":
    console.error(`[witness-verify] TAMPER — ${outcome.reason}.`);
    process.exit(1);
  default:
    console.error(`[witness-verify] internal error: unknown outcome ${JSON.stringify(outcome)}`);
    process.exit(4);
}
