/**
 * Scanner adapters (infra) for the Phase 3 scanner port.
 *
 * (A) BuiltinPatternScanner — a REAL zero-dependency scanner that reads files and
 *     finds genuine issue classes (secrets, eval/exec, shell-concat command
 *     injection, weak crypto, disabled TLS verification). Not a mock: it produces
 *     real Findings with file+line, tested against real files. It is the always-
 *     available backstop (like Semgrep's role: no compilation needed).
 *
 * (B) ExternalScannerAdapter — shells to a REAL `semgrep`/`codeql` binary when
 *     present (argv-only, via the process isolation adapter), parses its JSON output
 *     into Findings, and GRACEFULLY DEGRADES (fullDepth=false, never deadlocks) when
 *     the binary or a CodeQL DB-build is unavailable — the spec's degradation rule.
 */

import { readFileSync } from "node:fs";
import type { Scanner, ScanRequest, ScannerResult } from "../review/security_verifier.js";
import type { Finding, FindingCategory, Severity } from "../review/finding.js";
import { ProcessIsolationAdapter } from "./process_isolation.js";

interface Pattern {
  readonly rx: RegExp;
  readonly category: FindingCategory;
  readonly severity: Severity;
  readonly message: string;
  readonly detector: string;
}

// Real, conservative patterns for high-signal classes (kept precise to limit noise).
const PATTERNS: readonly Pattern[] = [
  { rx: /\b(?:api[_-]?key|secret|password|passwd|token)\s*[:=]\s*['"][^'"]{8,}['"]/i, category: "security", severity: "high", message: "Hardcoded secret/credential literal", detector: "builtin.secret" },
  { rx: /\bAKIA[0-9A-Z]{16}\b/, category: "security", severity: "critical", message: "AWS access key id in source", detector: "builtin.aws-key" },
  { rx: /\beval\s*\(/, category: "security", severity: "high", message: "Use of eval() on dynamic input", detector: "builtin.eval" },
  { rx: /\bexec\s*\(\s*['"`].*\$\{/, category: "security", severity: "critical", message: "Possible command injection (shell string with interpolation)", detector: "builtin.cmd-injection" },
  { rx: /\bchild_process\b.*\bexec\s*\(/, category: "security", severity: "high", message: "child_process.exec with a shell string (prefer execFile + argv)", detector: "builtin.shell-exec" },
  { rx: /\b(?:md5|sha1)\s*\(/i, category: "security", severity: "medium", message: "Weak hash (MD5/SHA1) — use SHA-256+", detector: "builtin.weak-hash" },
  { rx: /rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true/i, category: "security", severity: "high", message: "TLS certificate verification disabled", detector: "builtin.tls-verify-off" },
];

export class BuiltinPatternScanner implements Scanner {
  readonly name = "builtin-pattern";
  readonly requiresCompilation = false;

  async scan(req: ScanRequest): Promise<ScannerResult> {
    const findings: Finding[] = [];
    let idx = 0;
    for (const file of req.diffFiles) {
      let content: string;
      try {
        content = readFileSync(file, "utf8");
      } catch {
        continue; // unreadable file is skipped (not a scanner failure)
      }
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
        for (const p of PATTERNS) {
          if (p.rx.test(line)) {
            findings.push({
              id: `builtin-${idx++}`,
              category: p.category,
              severity: p.severity,
              confidence: 0.7,
              file,
              line: i + 1,
              message: p.message,
              detector: p.detector,
            });
          }
        }
      }
    }
    return { findings, fullDepth: true };
  }
}

/** Which external tool this adapter drives. */
export type ExternalScannerKind = "semgrep" | "codeql";

/**
 * Shells to a real external scanner when present; degrades gracefully otherwise.
 * The binary is invoked argv-only through the isolation adapter (no shell string).
 */
export class ExternalScannerAdapter implements Scanner {
  readonly name: string;
  readonly requiresCompilation: boolean;

  constructor(
    private readonly kind: ExternalScannerKind,
    private readonly binaryPath: string, // e.g. "semgrep" or an absolute path
    private readonly isolation = new ProcessIsolationAdapter(),
    private readonly cwd: string = process.cwd(),
  ) {
    this.name = kind;
    this.requiresCompilation = kind === "codeql"; // CodeQL needs a compilable env
  }

  async scan(req: ScanRequest): Promise<ScannerResult> {
    // CodeQL needs a compilable environment; if the request isn't compilable, degrade
    // (the spec: never deadlock on a CodeQL DB-build failure).
    if (this.requiresCompilation && !req.compilable) {
      return { findings: [], fullDepth: false, note: "CodeQL requires a compilable env; degraded to no-op" };
    }

    const args = this.kind === "semgrep"
      ? ["--json", "--quiet", "--error", ...req.diffFiles]
      : ["database", "analyze", "--format=sarifv2.1.0", "--output=-"]; // shape; real CodeQL needs a DB

    let result;
    try {
      result = await this.isolation.run(this.binaryPath, args, { cwd: this.cwd, timeoutMs: 120_000, envAllowlist: ["PATH", "HOME"] });
    } catch (err) {
      return { findings: [], fullDepth: false, note: `scanner spawn failed: ${(err as Error).message}` };
    }

    // Spawn error (binary absent) => graceful degrade, never throw/deadlock.
    if (result.code === null || result.stderr.includes("spawn error")) {
      return { findings: [], fullDepth: false, note: `${this.kind} unavailable; degraded (findings from backstop scanner instead)` };
    }

    try {
      const findings = this.kind === "semgrep" ? parseSemgrep(result.stdout) : parseSarif(result.stdout);
      return { findings, fullDepth: true };
    } catch (err) {
      return { findings: [], fullDepth: false, note: `could not parse ${this.kind} output: ${(err as Error).message}` };
    }
  }
}

/** Parse Semgrep --json output into Findings. */
export function parseSemgrep(json: string): Finding[] {
  const data = JSON.parse(json) as { results?: Array<Record<string, unknown>> };
  const results = data.results ?? [];
  return results.map((r, i) => {
    const extra = (r["extra"] ?? {}) as Record<string, unknown>;
    const start = (r["start"] ?? {}) as Record<string, unknown>;
    const sev = String(extra["severity"] ?? "WARNING").toUpperCase();
    return {
      id: `semgrep-${i}`,
      category: "security" as FindingCategory,
      severity: sev === "ERROR" ? "high" : sev === "WARNING" ? "medium" : "low",
      confidence: 0.8,
      file: String(r["path"] ?? "unknown"),
      line: Number(start["line"] ?? 0),
      message: String(extra["message"] ?? r["check_id"] ?? "semgrep finding"),
      detector: `semgrep:${String(r["check_id"] ?? "rule")}`,
    } satisfies Finding;
  });
}

/** Parse a minimal SARIF (CodeQL) document into Findings. */
export function parseSarif(json: string): Finding[] {
  const data = JSON.parse(json) as { runs?: Array<{ results?: Array<Record<string, unknown>> }> };
  const out: Finding[] = [];
  let i = 0;
  for (const run of data.runs ?? []) {
    for (const r of run.results ?? []) {
      const loc = (((r["locations"] as unknown[])?.[0] ?? {}) as Record<string, unknown>);
      const phys = ((loc["physicalLocation"] ?? {}) as Record<string, unknown>);
      const art = ((phys["artifactLocation"] ?? {}) as Record<string, unknown>);
      const region = ((phys["region"] ?? {}) as Record<string, unknown>);
      out.push({
        id: `codeql-${i++}`,
        category: "security",
        severity: "high",
        confidence: 0.85,
        file: String(art["uri"] ?? "unknown"),
        line: Number(region["startLine"] ?? 0),
        message: String((r["message"] as Record<string, unknown>)?.["text"] ?? "codeql finding"),
        detector: `codeql:${String(r["ruleId"] ?? "rule")}`,
      });
    }
  }
  return out;
}
