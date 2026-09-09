/** Test-only contract probe. It never enters product/package source and can never mint microVM authority. */
import type { TestRunResult } from "../../src/solve/validate.js";
import type { ExecutionSpec } from "../../src/isolation/isolated_executor.js";
import { resolvedWithinProject } from "../../src/infra/process_isolation.js";
import {
  microvmContainmentDecision,
  type MicrovmContainmentContract,
  type MicrovmRequestedEffect,
} from "../../src/infra/microvm_boundary.js";

export interface MicrovmContractProbe {
  readonly effect: MicrovmRequestedEffect;
  readonly perform: () => Promise<TestRunResult>;
}

export function buildContractEnforcingFakeMicrovmBoundary(contract: MicrovmContainmentContract) {
  return async (probe: MicrovmContractProbe, execSpec: ExecutionSpec): Promise<TestRunResult> => {
    const ref = execSpec.repoRef === "" || execSpec.repoRef === "." ? contract.projectDir : execSpec.repoRef;
    if (!resolvedWithinProject(contract.projectDir, ref)) {
      return { results: [], runnerError: `test scope escapes the project dir (${execSpec.repoRef}) — refusing` };
    }
    const decision = microvmContainmentDecision(contract, probe.effect);
    if (!decision.allowed) return { results: [], runnerError: `[TEST-ONLY fake microvm boundary] ${decision.reason}` };
    return probe.perform();
  };
}
