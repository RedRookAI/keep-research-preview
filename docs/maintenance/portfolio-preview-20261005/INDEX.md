# Current downloadable preview with a useful first result

Active goal, October 5, 2026 (UTC date verified). User requirements: publish the current Keep preview, make it a compelling portfolio piece for someone downloading it, preserve shared-host workloads, and use research → scoped implementation → vet per ticket. Existing requirements: exact source/artifact identity, protected installs, preserved old assets, no inflated qualification claims. Assumption: a repeatable Linux x64 walkthrough without an account is the earliest useful result; real-provider quality and production/organization rollout remain separate.

Project acceptance: a visitor verifies the new download, installs without a contributor checkout or Rust/C compiler, runs a repository walkthrough that shows approval, a materialized edit, passing tests, a diff, restart without replay and veto/source preservation, then can inspect its retained artifacts or configure their own repository. Scripted responses are disclosed before execution. Recovery remains available. The exact package and source are qualified, publicly downloadable and byte-verified; docs agree with the selected version. No paid requests or shared-host changes.

## Dependency order and status

| Ticket | Result | Dependency supplying required input | Planning status |
|---|---|---|---|
| [PF001](PF001.md) | An inspectable installed repository walkthrough | Reuse completed IS001 CLI/journey; no unfinished ticket prerequisite | Actionable, candidate audited |
| [PF002A](PF002A.md) | Current solve setup refusal is correctly checked by the full profile | PF001 supplies the supported installed solve contract | Actionable; two stale probes found during PF002 |
| [PF002](PF002.md) | Exact current source and clean installed package qualify | PF001 supplies packaged command, guide and versioned source; PF002A supplies reconciled probes | Actionable after PF001 |
| [PF003](PF003.md) | Visitor can acquire and run the matching public preview | PF002 supplies qualified immutable archives, checksums and receipts | Actionable after PF002 |

Use one implementation agent, serial product work. Implementation is authorized by the user's activated goal. These tickets do not authorize paid calls, additional dependencies, VMs, accounts, host policy/enforcement, shared-service restart or unrelated workspaces. Inherit the existing 2CPU/4GiB/0swap/512PID test profile and original 7200-second allowance, with 4820.387784691072 seconds already accounted; do not reset it. Record new measured attempts. If remaining allowance cannot cover a necessary check, report the gap and request an explicitly revised allowance.

## Shared research and approach

ArXiv checked first October 5: [SWE-bench](https://arxiv.org/abs/2310.06770), submitted October 10, 2023, revised November 11, 2024, evaluates changes against actual repository tests; [SWE-agent](https://arxiv.org/abs/2405.15793), submitted May 6, 2024, revised November 11, 2024, studies repository interaction and execution interfaces. Applicability: demonstrate an actual inspected patch and observed tests, not a model's success assertion. Neither paper qualifies Keep or justifies benchmark/performance claims for scripted responses.

Current primary [npm pack](https://docs.npmjs.com/cli/v11/commands/npm-pack/) and [lifecycle](https://docs.npmjs.com/cli/v11/using-npm/scripts/) documentation reopened today: use ordinary scripts-enabled package creation and clean installation, preserving source/build/archive identities. Existing R002/R003/R005 release work is reusable for a new version; its 0.0.5 receipts remain historical, not inherited qualification. Inspect actual pinned npm behavior as well as current docs.

Actual consumers inspected: src/cli/keep.ts, src/cli/cli_core.ts, src/cli/recovery_demo.ts, acceptance/installed_solve.mjs, tools/qualify_exact_revision.mjs, tools/run_installed_golden_journeys.mjs, docs/quickstart.md and existing release receipts. IS001 already executes a useful installed owner workflow with two controlled loopback responses; it was not shipped in the 0.0.5 download. Current quickstart still advertises that older download and its source-version header is stale. Reuse the real project runtime and that authored fixture, with a small CLI presenter; retain recovery and all existing authority/pricing gates.

Alternative considered: ship documentation alone, requiring visitors to configure an actual provider first. It leaves account/setup/spend friction before a useful result. A disclosed walkthrough offers a reproducible first result and a clear next step without introducing a separate agent engine, installer, UI stack or paid benchmark. No staged transcript presented as live-model output.

Consequential effects: a scripted demonstration can be mistaken for model quality, so label responses and simulated operator decisions before execution; actual patch/test/approval evidence remains inspectable. New CLI code requires one new source version, proposed 0.0.12-preview.1, and a fresh native/package build and exact qualification. Preserve old releases and do not turn artifact publication into production endorsement. If a material runtime defect is found, create a separate scoped ticket and leave its dependent qualification unconfirmed rather than expanding these tickets silently.

## Plan audit and stopping point

Coverage is complete for the requested preview: first-use behavior PF001, exact build/install evidence PF002, acquisition/docs/publication PF003. No dependency cycles or duplicate IS001/security remediation; no new infrastructure. The initial portfolio result is PF001 and can be tried with `keep demo project` once built. Later model-quality work may be informed by visitor feedback, but is not activated here. Finish when all three tickets meet their own acceptance and the integrated public download journey passes. Preserve state at meaningful private Git checkpoints.
