/**
 * Infra composition root (infra) — the single swap-in point for live adapters.
 *
 * `composeInfra` assembles the real infra adapters behind their ports from a policy
 * config. On the connected (Hetzner) environment, this is the ONE place to replace
 * local/stub adapters with live ones (HTTP provider, git remote, real semgrep,
 * microVM isolation, HTTP MCP/A2A) — domain code keeps depending only on the ports.
 */

import type { Spine } from "../spine/spine.js";
import { GitAdapter } from "./git_adapter.js";
import { ProcessIsolationAdapter } from "./process_isolation.js";
import { BuiltinPatternScanner, ExternalScannerAdapter, type ExternalScannerKind } from "./scanner_adapter.js";
import type { Scanner } from "../review/security_verifier.js";
import { TriggerRouter } from "../ecosystem/integrations.js";
import { registerAllTrackers } from "./tracker_adapters.js";
import { CapabilityHub, type CapabilityAuthorizationVerifier } from "../ecosystem/capability_port.js";

export interface InfraConfig {
  readonly spine: Spine;
  /** If set, a GitAdapter is created for this repo working directory. */
  readonly repoDir?: string;
  /** External scanner binaries to wire (e.g. {semgrep: "semgrep"}); absent => builtin only. */
  readonly externalScanners?: Partial<Record<ExternalScannerKind, string>>;
  /** cwd for external scanners; defaults to repoDir or process.cwd(). */
  readonly scannerCwd?: string;
  readonly capabilityAuthorizationVerifier?: CapabilityAuthorizationVerifier;
}

export interface KeepInfra {
  readonly git?: GitAdapter;
  readonly isolation: ProcessIsolationAdapter;
  /** Builtin backstop first, then any external scanners (degrade gracefully). */
  readonly scanners: readonly Scanner[];
  readonly triggers: TriggerRouter;
  readonly capabilities: CapabilityHub;
}

/** Assemble the infra bundle from policy. Only the pieces the config asks for. */
export function composeInfra(config: InfraConfig): KeepInfra {
  const isolation = new ProcessIsolationAdapter();

  const scanners: Scanner[] = [new BuiltinPatternScanner()]; // always-available backstop
  const scannerCwd = config.scannerCwd ?? config.repoDir ?? process.cwd();
  for (const [kind, binary] of Object.entries(config.externalScanners ?? {})) {
    if (binary) scanners.push(new ExternalScannerAdapter(kind as ExternalScannerKind, binary, isolation, scannerCwd));
  }

  const triggers = new TriggerRouter();
  registerAllTrackers(triggers);

  const capabilities = new CapabilityHub(config.spine, () => Date.now(), config.capabilityAuthorizationVerifier);

  const infra: KeepInfra = {
    isolation,
    scanners,
    triggers,
    capabilities,
    ...(config.repoDir !== undefined ? { git: new GitAdapter(config.repoDir) } : {}),
  };
  return infra;
}
