# One reproducible repository case using existing Codex access

Goal activated October 7, 2026. User requirement: use Codex for this work; no separate paid model/API provider. Preserve shared-host workloads and research → implement → vet per ticket. The prior portfolio preview remains complete and immutable. This batch ends with one documented real-model attempt through an installed Keep package; success is claimed only if independently checked task tests pass. An unsuccessful evaluated attempt must remain visible and does not qualify model quality.

## Dependency order

| Ticket | Output | Dependency | Status |
|---|---|---|---|
| [CS001](CS001.md) | Verified task baseline and a supported Codex integration decision | Existing public release and dated research | Confirmed investigation; compatibility decision recorded |
| [CS002](CS002.md) | One owner-installed solve can obtain genuine Codex output without a separate API key | CS001 supplies compatible usage/authority/limit contract | Provisional until those decisions are resolved |
| [CS003](CS003.md) | One real-model task has an inspectable patch and independent outcome | CS002 supplies installed working Codex path; CS001 frozen task/checker | Provisional |
| [CS004](CS004.md) | Public package/source/docs and case evidence agree | CS002 tested code, CS003 honest observed outcome | Provisional; new-code artifact qualification needs approved allowance |

Existing scope/output reused: PF001/PF002/PF003 installed demo/package/release machinery and IS001 project approval/proposal workflow. Do not reopen their source-bound evidence or build a benchmark service, install SDK dependencies, create a VM, change global Codex settings/auth, or interfere with another instance. Use one agent and serial product work. Public publication and private backups follow the existing project protocol.

## Dated evidence and approach

UTC verified October 7. Reused today's arXiv-first [SWE-bench paper](https://arxiv.org/abs/2310.06770) (October10,2023; revised November11,2024) and [primary documentation](https://www.swebench.com/SWE-bench/): freeze a real issue and check failing-to-passing plus preserved tests. Their framework informs the checking method; this historical JavaScript case is not an official SWE-bench score or proof of general model quality.

Official OpenAI [authentication](https://learn.chatgpt.com/docs/auth), [non-interactive mode](https://learn.chatgpt.com/docs/non-interactive-mode) and [app-server](https://learn.chatgpt.com/docs/app-server) inspected October7. Codex CLI0.159.3 is present and reports ChatGPT login. Official `codex exec` supports existing-login reuse and structured final output. No generation request was sent. Subscription access has its own allowance/limits; do not invent a per-token API bill, zero total cost or unlimited quota. No raw auth-token extraction, unofficial OAuth/API forwarding, account changes, credit purchases, auth-file copying to a project/public CI or global-config edits.

Verified code: src/cli/runtime_config.ts accepts only local/openai-compatible/anthropic-compatible; local is a stub. src/gateway/gateway.ts defines ModelProvider generation/usage. src/cli/keep.ts wires installed owner/organization descriptors; src/scheduler/metered_provider.ts and src/observability/cost_model.ts require legitimate USD pricing rather than treating unknown prices as zero. Therefore existing Codex CLI login does not establish a working Keep backend. Local CLI launch still invokes a remote service; it must not be labeled air-gapped. Use the existing CLI without adding the SDK unless a concrete requirement demands otherwise.

Installed protocol schemas have no direct maxTokens/maxOutputTokens fields in ThreadStartParams/TurnStartParams. This does not prove no configuration can bound output; caller token ceilings, internal retries/tools and subscription accounting are explicit unresolved design questions for CS001. Do not silently relax the existing contracts or route subscription credentials through the HTTP/API adapter. Prefer one generation-only owner solve path; preserve existing configured API and embedding behavior.

## Frozen task and independent checks

Candidate selected before model execution: [escape-string-regexp issue20](https://github.com/sindresorhus/escape-string-regexp/issues/20), reported March12,2020. Actual failing release: v2.0.0, commit21c557c7f14a112eebe196abd98d085f5fcfcf5e, MIT, no production dependencies. V3.0.0 was inspected and already fixes Unicode escaping, so it is not the failing base. Historical solution knowledge/possible model training overlap is disclosed; no novelty/decontamination claim. The coding request must receive only the issue and failing source, never a reference implementation or solution patch.

Node22.23.2 baseline reproduced one failing Unicode-hyphen check and two passing checks: maintainer main escaping assertion (mechanically adapted from AVA to built-in Node assert) and empty/non-string behavior. No npm dependencies were installed. The checker and source hashes are retained before inference. Hyphen encoding intentionally needs to change; the old exact hyphen-output assertion is not an unchanged compatibility promise, and the full upstream AVA suite was not run. Check semantic literal matching, original metacharacter behavior and input rejection independently of the model-generated goal test.

## Acceptance, allowance and plan audit

Observable end result: an installed `keep solve` uses Codex's supported existing ChatGPT login, requires sample approval before dispatch, produces a reviewable proposal or explicit failed outcome, and leaves the source unmodified pending a bound decision. Record independent before/after checks, source/package/CLI identity, visible requests/turns/token usage and unknown internal/account-cost facts, cancellation/uncertainty, and the first attempt. Publish reproducible setup/commands/diff/results; retain all failed attempts. This one case does not qualify production isolation, organization authority or general success rate.

The original7200-second cumulative test envelope has about239 seconds left. It is not reset by this goal. Keep existing2CPU/4GiB/0swap/512PID containment and no model/API spending changes. Additional full source/native/new-package qualification needs an explicitly approved extension. Proposed extension for review:1800 additional test wall seconds (30minutes), total9000 seconds, same controls; not yet authorized or installed. Preparation and read-only work can continue meanwhile.

Coverage: CS001 resolves actual prerequisites; CS002 delivers one coherent supported operation including necessary billing/authority compatibility; CS003 verifies the real task; CS004 publishes the integrated result. No cycles or duplicate preview work. A thin supported CLI adapter is preferable to a new provider framework, but remaining interface questions must be resolved before CS002 becomes actionable. Any material unrelated defect gets a separate small ticket. Version stays0.0.12-preview.1 for planning/docs; code publication uses the established next-checkpoint bump, with separate exact-artifact qualification.

[CS001 compatibility decision](CS001-decision.md) is confirmed as an investigation result. The next implementation question is explicit subscription admission at the project/gateway seam. Integration, actual model attempt and new package qualification remain unconfirmed.

## Resource approval handoff

Goal is blocked pending the requested additional30minutes of cumulative server-test runtime. The original7200-second envelope has about189seconds remaining and is preserved. User working principle7 prohibits silently extending it. The upstream bug baseline and Codex compatibility investigation are saved; a private bounded transport prototype typechecks and passes10controlled CLI-fixture checks. It is not installed solve integration, actual model evidence or a release. CS002/CS003/CS004 remain unconfirmed. No real case-model requests or separate API spending. Resume the same full objective after resource approval; do not activate a substitute goal.
