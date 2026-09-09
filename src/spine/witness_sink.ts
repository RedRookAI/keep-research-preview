/**
 * Witness sink (Build Step 1 — making the spine anchor LIVE).
 *
 * The spine's hash-chain is tamper-EVIDENT, but `verifyChain` alone cannot catch a
 * TRUNCATION (delete recent blocks → still a valid shorter chain) or a FORK
 * (rebuild history → still internally consistent). `checkAgainstWitness` catches
 * both — but only if a witness was actually PUBLISHED somewhere independent and is
 * later compared. This port is that independent location.
 *
 * DESIGN (SOTA + cross-industry, 2026-08-08):
 *  - Transparency-log witnessing (CT / RFC 6962 / C2SP tlog-witness): publish each
 *    checkpoint; a new checkpoint is trusted only if it is a consistent FORWARD
 *    EXTENSION of the last one. The deployed answer to split-view/equivocation is
 *    witness COSIGNING by a quorum (gossip was never deployed).
 *  - NIST/WORM immutable audit logs: append-only, no single entity holds both write
 *    and delete, "replication with consensus: multiple independent copies must
 *    agree", and above all — make tampering *operationally detectable*.
 *
 * N=1 vs FLEET (two logical alternatives behind ONE port):
 *  - N=1 (in-env, BUILT): a LOCAL append-only file, SEPARATE from the chain, held
 *    outside the agent's write-set (R7/R10). This gives DETECTION (compare the chain
 *    to an independently-held witness) — the honest notary-log guarantee. It does NOT
 *    give split-view resistance: a full-host compromise can tamper both. Labeled
 *    best-effort in-env.
 *  - FLEET (SEAM): independent witnesses on other hosts that COSIGN each checkpoint
 *    (the tlog-witness quorum) → real split-view resistance. Needs a second location +
 *    network + key custody — declared SEAM, not built here.
 */

import { appendFileSync, readFileSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { ChainWitness } from "./hashchain.js";

export interface WitnessSink {
  /** Append-only publish of a witness (the head checkpoint). */
  publish(w: ChainWitness): void;
  /** The most-recently published witness, or undefined if none. */
  latest(): ChainWitness | undefined;
  /** All published witnesses in publish order (for reconcile/audit). */
  history(): readonly ChainWitness[];
}

/** In-memory sink (tests + deterministic in-env runs). */
export class InMemoryWitnessSink implements WitnessSink {
  private readonly log: ChainWitness[] = [];
  publish(w: ChainWitness): void {
    this.log.push(w);
  }
  latest(): ChainWitness | undefined {
    return this.log.length > 0 ? this.log[this.log.length - 1] : undefined;
  }
  history(): readonly ChainWitness[] {
    return this.log.slice();
  }
}

/**
 * Local file sink (N=1 in-env): a JSONL file SEPARATE from the chain. To be a real
 * independent location it must live outside the agent's write-set (R7/R10); passing a
 * path the agent cannot reach is the deployment's responsibility (kernel belt = SEAM).
 */
export class FileWitnessSink implements WitnessSink {
  private readonly path: string;
  constructor(dataDir: string, filename = "witness.jsonl") {
    this.path = join(dataDir, filename);
    const dir = dirname(this.path);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    if (!existsSync(this.path)) writeFileSync(this.path, "");
  }
  publish(w: ChainWitness): void {
    appendFileSync(this.path, JSON.stringify(w) + "\n");
  }
  latest(): ChainWitness | undefined {
    const all = this.history();
    return all.length > 0 ? all[all.length - 1] : undefined;
  }
  history(): readonly ChainWitness[] {
    if (!existsSync(this.path)) return [];
    const out: ChainWitness[] = [];
    for (const line of readFileSync(this.path, "utf8").split("\n")) {
      const t = line.trim();
      if (t.length > 0) out.push(JSON.parse(t) as ChainWitness);
    }
    return out;
  }
}
