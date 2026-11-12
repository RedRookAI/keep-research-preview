# Keep

**A self-hosted platform for AI work, persistent knowledge and governed execution.**

Keep brings project goals, memory, reusable skills and execution records into one runtime. It carries work across sessions, checks proposed changes and preserves the decisions needed to review or recover a run. Its implementation spans software development, research, knowledge management and content workflows.

The repository workflow shows the core in action: Keep edits a separate workspace, runs executable checks, presents the exact diff for approval or veto, and exports the evidence. Recovery records preserve uncertain operations so a restart can inspect what happened before retrying.

## Explore Keep

1. **Try a checked code change.** Open your assigned invitation, choose **Start demo**, then **Prepare the fix**. Keep repairs a webhook handler that counts repeated deliveries twice. Inspect four executed checks and the diff, approve or veto the proposal, then download the evidence. The sample uses two authored responses and requires no AI account or paid calls. Use the invitation credential supplied separately by the operator. This reviewer endpoint is separate from existing owner invitations.

https://keep-b.redrook.ai/console

2. **See the genuine Codex case.** Read the retained Unicode-regex fix, actual patch, unchanged checker and execution record. The patch and three checks can be inspected or reproduced without a Keep account. This historical case used real generation.

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/genuine-codex-walkthrough.md

3. **Inspect the engineering.** Follow the architecture guide into execution, proposal review, persistence and recovery code, with the relevant tests.

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/architecture.md

4. **Run the supported appliance locally.** The self-contained Linux x64 download includes its Node runtime, sandbox helper and generation engine. Host prerequisites are Python 3.8+, OpenSSH, QEMU tools, existing KVM access and at least 8 GiB free at first startup after extraction. Read the start guide before downloading.

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/reviewer-appliance.md

https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-reviewer-2026-11-12.3

## Current snapshots

| Subject | Version | Scope |
|---|---|---|
| Development source | 0.0.29-preview.1, tested code 70bdde3 | Current source changes; source checks use Node >=22.23.5 <23. Full native builds additionally require the documented Rust/C toolchain. |
| Hosted demo | 0.0.25-preview.1, source 8e8eeaa | Prepared webhook task with real edits, four checks, approval/veto and evidence export. Assigned invitation required. |
| Linux x64 appliance | 0.0.29-preview.1, frozen runtime 253fbca / assembly 73fabd7 | Exact archive checked on fresh CI for the account-free browser workflow, export and restart. New development-source changes are separate. |
| Historical direct Node download | 0.0.21-preview.1 | Earlier archive and its own installation receipts. |

The broader platform remains under development. The table below separates implemented mechanisms from observed readiness. The existing appliance's matching source companion includes all 289 required source/version pairs. Its native OpenClaw API observation used dispatch paused and zero provider calls; fresh live-account generation remains untested.

The tested source passed 347 cases in its partial CI profile on Node 22.23.5. The final reviewer invitation passed fresh sign-in and retains an unused task. Exact source, hosted and appliance subjects:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/qualification/submission-snapshot-2026-11-12.json

Walkthrough, artifact evidence and source-build instructions:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/guided-demo.md

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/qualification/appliance-29-2026-11-12.md

https://github.com/RedRookAI/keep-research-preview/blob/main/WORKFLOW.md

## Scope and implementation status

| Area | Implemented scope | Current status |
|---|---|---|
| Project orchestration | Typed state, dependency-aware plans and task contracts, bounded execution, approval waits, cancellation and restart recovery. | Composed into the runtime. An ordinary software run admits one root task; a separate goal coordinator schedules bounded task contracts. General project completion needs broader qualification. |
| Software delivery | Pinned revisions, separate workspaces, structured edits, executable checks, exact-proposal decisions, local source landing and revert; native-captured patch candidates with retained application evidence. | Installed proposal/review workflow demonstrated. The guided demo supports approval and veto. Landing, revert and interrupted-operation recovery have focused tests. |
| Memory and knowledge | Encrypted persistent custody, source provenance, creation/correction, scoped retrieval, retention controls, temporal relationships and task-context assembly. | Durable memory commands and selected retrieval paths have scoped checks. Conversational memory and automatic learning have separate persistence and configuration limits. |
| Research and retrieval | Bounded research coordination, citation records, freshness checks, corpus ingestion and lexical/vector retrieval. | Components and configured routes are implemented. Live source access depends on supplied adapters and permissions. |
| Skills and learning | Trajectory extraction, validation, comparison against a baseline, content-bound admission, monitored reuse, retirement and regression response. | Managed lifecycle and persistence are implemented. Execution validation needs a configured oracle; useful reuse requires workload-specific measurement. |
| Providers and resource control | Local/remote adapters, routing and cascades, cancellation, spending reservations, usage settlement and retained uncertainty. | Selected generation and embedding routes have checks. The default local provider is an offline fixture. Trace totals distinguish known cost from unknown usage/pricing; monetary coverage varies by route. |
| Authority and governance | Permissions, delegation, consequence gates, privacy/egress controls, audit records, tenant-scoped decisions, attributable memory controls and evidence export; organization code/PKCE login with pinned key refresh and session checks. | Controls govern specific entry points. Live organization deployment, current membership, independent custody and complete effect-path coverage remain open. |
| Clients and operations | CLI, authenticated gateway, browser submission/review console, saved-instance restricted OpenClaw credentials, traces and protected backup/restore interfaces. | Credentials preserve the saved repository, checker, model, limits and usage history. Combined archive startup, instance lifecycle, console and historical plugin setup have installed checks. Current native OpenClaw submission/status passed a paused SDK fixture. Fresh account/CLI handover, offsite recovery and wider operational qualification remain open. |
| Domain workflows and adaptation | Stage contracts for fiction, academic papers, chapter books, social video and audiobooks; optional model adaptation and training interfaces. | Experimental. External effects need configured capabilities. Weight training requires an external backend. Automatic adapter promotion refuses absent screening, sandbox and replay evidence; complete installed domain workflows remain to be qualified. |
| Execution isolation | Process controls, an opt-in required namespace jail, native protocol/capture code and microVM probes. | Selected Linux jail behavior has scoped checks. The packaged native supervisor provides a refusal exchange; production native authority and independent attestation remain unfinished. |

The composition root connects these subsystems and exposes their configuration requirements:

https://github.com/RedRookAI/keep-research-preview/blob/main/src/compose.ts

## Demonstrated behavior

The account-free repository walkthrough makes a real workspace edit, runs executable checks and displays the proposed diff. It exercises approval, restart recovery, wrong-token refusal and veto. The responses are authored locally; the reviewer makes the proposal decision through Keep's controls. Hosted approval applies the change to the synthetic source repository. The local appliance retains the reviewed workspace and preserves its source repository.

Recording and execution details:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/portfolio-demo.md

A separate case used real Codex generation to produce a Unicode-regex fix. All three unchanged predefined checks passed. Native OpenClaw submitted and recovered the job, and Keep's browser controls supplied approval and exact-proposal veto. OpenClaw tool selection was scripted; the decisions were developer-administered. This result covers one integration case.

Patch, checks and historical execution record:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/genuine-codex-walkthrough.md

## Run the installed preview

The recommended reviewer download is the self-contained .29 Linux x64 appliance. It supplies the runtime and required sandbox inside its VM and needs existing QEMU/KVM access on the host.

https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-reviewer-2026-11-12.3

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/reviewer-appliance.md

The earlier .21 combined archive remains available for the separate direct Node installation route. The combined Linux x64 download contains Keep, bundled TypeScript, the measured generation-only Codex engine and the restricted OpenClaw plugin. Extract it and select the documented Node 22 runtime. This route starts directly from the archive.

```sh
./bin/keep demo project
```

Installation, runtime prerequisites and account-free walkthrough:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/quickstart.md

For your own authorized public repository, configure the generation provider, repository revision and check command. The CLI and OpenClaw client use the same project runtime. The browser console shows pending decisions, proposed changes, checks and recorded delivery outcomes.

Codex setup:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/codex-project.md

Instance and console:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/local-instance.md

OpenClaw setup:

https://github.com/RedRookAI/keep-research-preview/blob/main/integrations/openclaw/README.md

## Release status and remaining work

Fresh-workspace checks reproduced the .21 download and the standard .22 source build on separate Ubuntu x64 VMs. The rebuilt native binaries matched the published checksums. Spark ARM64 checks passed the portable workflow. Actual offline dependency preparation subsequently passed on fresh Ubuntu 22.04 x64 runners using the public download and source .22. Restricted Ubuntu 24.04 sandbox setup remains open; source .22 now detects that setup failure before launching npm.

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/qualification/preparation-portability-2026-11-12.md

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/qualification/independent-preview-2026-11-12.md

The 0.0.21-preview.1 combined payload passed unprivileged startup, both account-free demos, instance/console lifecycle, authenticated proposal export and real offline TypeScript preparation. It includes freshly built native executables and the unchanged measured generation engine. The receipt records each tested subject and reuse of identical payload bytes. Historical full-suite results remain attached to their tested revisions.

Exact release identities and qualification:

https://github.com/RedRookAI/keep-research-preview/blob/main/KEEP_RELEASE.md

Completion work includes simpler setup, complete installed consumers across the broader platform, consistent build/CI verification, wider real-task evaluation and operational recovery. Organization deployments also need live identity, credential/signing separation and qualified isolation.

Current source adds saved Codex setup through `keep instance init`, with explicit engine/model/limits and actionable prerequisite failures. Self-improvement now requires executed capability and safety checks before promotion; missing, empty or unusable evaluations hold the candidate. Source CI uses the supported Node range and checks actual test execution. The historical combined download and frozen appliance retain their own source identities; a source update does not replace their installed bytes.

Authenticated proposal export packages the retained diff, pinned source, check results, pseudonymous attribution and delivery observations for offline inspection. The source checker refuses a changed revision or dirty checkout.

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/proposal-export.md

November 11 source changes and validation:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/maintenance-2026-11-11.md

The measured release profile and evidence retain their observation dates. Current evidence covers developer-administered Linux fixtures and the single genuine repository case above. General model quality, independent security verification and macOS/Windows support remain unqualified.

Evidence and roadmap:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/evidence.md

https://github.com/RedRookAI/keep-research-preview/blob/main/ROADMAP.md

## Engineering approach

Keep separates generation, execution, verification and authorization. A model proposes content; the runtime controls state transitions and the relevant effect boundaries. Repository decisions bind to an exact proposal digest. Durable records preserve uncertain effects so recovery can inspect the original operation before retrying.

Ports separate domain logic from providers, storage and execution backends. Tests include permitted work, refused operations, changed source, persistence failures and interrupted effects. The host remains part of the trust boundary; each isolation mode has its own measured limits.

Architecture and security boundaries:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/architecture.md

https://github.com/RedRookAI/keep-research-preview/blob/main/SECURITY.md

Build instructions and component guides:

https://github.com/RedRookAI/keep-research-preview/blob/main/WORKFLOW.md

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/semantic-memory.md

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/skill-registry.md

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/monetary-accounting.md

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/backup.md

## People and licensing

Keep is a Red Rook AI project. Product direction and acceptance requirements are owner-led. Implementation, debugging, checks and documentation have been developed with substantial AI assistance, including Codex. Recorded results identify scripted fixtures and developer-administered decisions.

Keep's original code uses the MIT license. Third-party components retain their own terms.

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/licensing.md
