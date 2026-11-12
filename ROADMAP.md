# Project status and roadmap

Updated November 12, 2026. This page records the delivered preview, its observed behavior and the remaining product commitments.

## Current development

Development source is **0.0.29-preview.1**. The hosted guided demo runs **0.0.25-preview.1**; the latest Linux x64 appliance is **0.0.29-preview.1**. The appliance retains its own frozen guest-runtime and host-assembly sources, recorded separately in KEEP_RELEASE.md. Later source changes do not update the installed appliance or hosted demo.

The exact .29 appliance passed a fresh-machine browser workflow with approval and veto, four executable checks, evidence export and stop/restart with retained jobs. Its sample uses authored responses and makes zero paid model calls. Current native OpenClaw submission and fresh-process status also passed against the shipped Keep API with dispatch paused. That SDK observation made zero account/provider calls. Fresh live-account generation, complete owner handover and the broader platform remain open.

## Available to inspect

The **0.0.29-preview.1** appliance supplies Keep, Node, the required sandbox helper and the generation engine in a Debian guest. Use Linux x64 with Python 3.8+, OpenSSH, QEMU tools and existing read/write KVM access. First startup requires at least **8 GiB of free host storage after extraction**, in addition to the bundle already on disk. ARM64, macOS, Windows and other hypervisor profiles remain unqualified for this appliance.

Download and start guide:

https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-reviewer-2026-11-12.3

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/reviewer-appliance.md

Exact appliance and current SDK observations:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/qualification/appliance-29-2026-11-12.md

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/qualification/current-openclaw-api-2026-11-12.json

The hosted guided demo is available with an assigned invitation:

https://keep.redrook.ai/console

The historical **0.0.21-preview.1** combined Linux x64 archive remains available for the separate direct Node installation route. Its scoped startup, export and required-jail preparation receipts retain their original subject. See [the direct installation guide](docs/combined-preview.md) and [exact release identities](KEEP_RELEASE.md).

Delivered behavior and its evidence boundaries:

| Delivered capability | Observed result and limit |
|---|---|
| Genuine Codex repository work | One historical public issue produced a working patch and passed all three unchanged predefined checks. Native OpenClaw submitted and recovered the job; actual browser approval and exact veto preserved the original source. Codex generation was real; OpenClaw tool selection was scripted and decisions developer-administered. [Inspect the result](docs/genuine-codex-walkthrough.md). |
| Restricted OpenClaw client | Submission/status use the same Keep runtime, a separate expiring/revocable credential and a durable client journal. The two tools cannot approve or land a proposal. [Setup](integrations/openclaw/README.md). |
| Review and recovery | The console exposes pending steps, diffs, checks and exact decisions. Scoped installed checks cover refused authority, outage, cancellation without stopping another job, and synthetic protected recovery/upgrade. These are bounded observations, not universal containment or offsite recovery. [Evidence](docs/evidence.md). |
| Historical combined installation | The exact .20 archive passed unprivileged extraction/startup, both account-free demos, instance/console lifecycle and authenticated export/offline verification. Native/engine bytes and their dated evidence are carried unchanged. Those historical checks do not qualify later artifacts. [Qualification](docs/qualification/combined-preview-2026-11-11.json). |

The hosted and appliance walkthroughs use two authored responses and actual reviewer decisions. They produce real workspace edits, checks and review artifacts. Hosted approval applies the exact proposal to the synthetic source repository; appliance approval retains the reviewed workspace and preserves its source repository. Historical scripted-decision demos and the separate synthetic recovery experiment retain their original receipts. Configured memory, skills, usage admission and backup interfaces retain their own prerequisites and evidence limits.

## Remaining delivery priorities

The broader platform retains the commitments below. Current development improves client job continuity, private-data storage, skill consumption and recovery, while reusing the existing setup, evaluation-admission and source-CI mechanisms. Each change needs its own relevant checks; stronger-profile qualification remains separate.

1. **Make adoption easier.** Reduce manual setup for a new owner's supported Codex/OpenClaw repository workflow, including clear readiness failures and the required helper/runtime prerequisites. The shipped archive and existing walkthrough remain usable now.
2. **Deliver live organization identity and isolation.** Implement an attributable organization credential lifecycle, scoped non-human identity and tenant boundaries while preserving personal operation. Injected tenant fixtures do not establish these capabilities in a live deployment.
3. **Strengthen production execution and custody.** Complete the native authority, credential/signing separation and attestation requirements beyond the selected trusted-host namespace profile.
4. **Complete retained product consumers and operations.** Connect the remaining privacy, memory, skills, integrations, observability and recovery requirements below, with evidence for the supported installed behavior. Broader evaluation and platform parity remain open.

The direct Keep CLI and the account-free walkthrough remain part of that experience. OpenHands is relevant implementation prior art; it is not a selected runtime dependency or an additional required service.

## Broader product commitments

Keep is intended to support both individual owners and organizations. Personal operation must remain usable without organization-only infrastructure; organization operation needs its own authenticated identity, tenant isolation and custody evidence.

| Area | Remaining work |
|---|---|
| Execution and credentials | Admitted native execution, stronger isolation/attestation, separate signing and credential authority, and platform-specific conformance. |
| Identity and operations | Organization login, rotation/revocation, scoped non-human identities, agent discovery, tenant boundaries and operational observability. |
| Privacy and memory | Retention/erasure, controlled retrieval, private-data custody and authorization across project changes. |
| Skills and learning | Validated reuse, feedback and rollback, bounded research and adaptation, with measured usefulness and preserved safety constraints. |
| Integrations and clients | Framework-neutral control, governed triggers/notifications and external capabilities, broader client and domain workflows. |
| Governance and evidence | Complete usage coverage, threat interception, drift response, attributable compliance evidence and outside-principal witnessing. |
| Reliability and evaluation | Protected recovery, bounded state growth, structural integration, measured performance, reproducible builds and broader task evaluation. |

Completing one preview workflow does not complete these areas. Historical component tests and simulated organization fixtures do not establish live enterprise readiness. Stronger claims require the corresponding installed consumer, meaningful allowed/refused checks and attributable evidence.

See [architecture](docs/architecture.md), [security](SECURITY.md), [contributing](WORKFLOW.md) and [the current release](KEEP_RELEASE.md).
