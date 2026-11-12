# Keep

**A self-hosted platform for AI work, persistent knowledge and governed execution.**

Keep brings project goals, memory, reusable skills and execution records into one runtime. It carries work across sessions and keeps changes, checks and decisions available for review and recovery.

For repository work, Keep edits a separate workspace, runs executable checks and presents the diff for approval or veto. Its recovery records preserve interrupted and uncertain operations across restarts.

## Try Keep

**Open the demo directly. No sign-in or AI account is needed.**

https://keep-demo.redrook.ai/console

Choose **Start demo**, then **Prepare the fix**. Keep repairs a webhook handler that counts repeated deliveries twice. Review the diff and four checks, approve or veto the proposal, then choose **Download evidence**.

The demo uses two authored responses with real workspace edits and executable checks. It shares one disposable sample task; if a decision is already recorded, you can inspect the retained result and download its evidence. The downloadable appliance below gives you your own copy.

Walkthrough:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/guided-demo.md

## See a real Codex result

Keep used Codex to repair a Unicode-regex bug in escape-string-regexp. The record includes the generated patch, three predefined checks, an earlier unsuccessful attempt and the final proposal decision. You can inspect or reproduce the patch without a Keep account.

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/genuine-codex-walkthrough.md

## Capabilities

| Area | Implementation |
|---|---|
| Project execution | Dependency-aware plans, task contracts, approval waits, cancellation and restart recovery. |
| Software delivery | Pinned source revisions, separate workspaces, edits, executable checks, exact-proposal decisions, landing and revert. |
| Memory and knowledge | Encrypted persistent storage, source provenance, corrections, scoped retrieval, retention and task context. |
| Research | Research coordination, citations, freshness checks, document ingestion and lexical/vector retrieval through configured adapters. |
| Skills and learning | Skill extraction, validation, baseline comparison, content-bound admission, reuse, retirement and regression response. |
| Providers and costs | Local/remote adapters, routing, spending reservations and usage settlement. Traces retain unknown usage and pricing; metering coverage varies by route. |
| Authority | Permissions, delegation, privacy/egress controls, tenant-scoped decisions, audit records and organization code/PKCE login. |
| Clients and operations | CLI, authenticated gateway, browser console, restricted OpenClaw client credentials, evidence export and protected backup/restore. |
| Domain workflows | Stage contracts for research, fiction, academic papers, books, social video and audiobooks. External effects need configured capabilities. |
| Isolation and adaptation | An opt-in required Linux namespace jail, experimental native transport and microVM probes. Training uses an external backend port; automatic adapter promotion refuses missing provenance and execution evidence. |

The repository workflow is demonstrated. Broader installed workflows, live organization deployment and production native execution remain in development. The default local provider uses offline fixtures; live generation requires a configured provider.

## Inspect the engineering

The architecture guide links execution, proposal review, persistence and recovery code with the relevant tests. The source CI runs a partial profile; exact results and tested revisions are recorded in the submission snapshot.

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/architecture.md

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/qualification/submission-snapshot-2026-11-12.json

## Run locally

The self-contained **0.0.30-preview.1 Linux x64 appliance** includes Node, the sandbox helper and generation engine. The release receipt identifies the archive checked for approval, veto, evidence export and stop/restart.

The host needs Python 3.8+, OpenSSH, QEMU tools, existing KVM access and at least 8 GiB free at first startup after extraction. Read the start guide before downloading.

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/reviewer-appliance.md

https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-reviewer-2026-11-12.4

| Snapshot | Version |
|---|---|
| Development source | 0.0.30-preview.1 |
| Hosted demo | 0.0.30-preview.1, source 8f4f4da |
| Appliance | 0.0.30-preview.1; exact source and image hashes in its manifest |

The hosted demo and appliance retain their frozen code. Fresh live-account generation on the appliance remains untested. The release record contains exact hashes and the historical direct-install archives.

https://github.com/RedRookAI/keep-research-preview/blob/main/KEEP_RELEASE.md

Source contributors need Node 22.23.5 or later on Node 22. Full native builds also require the pinned Rust/C toolchain. Build and check commands:

https://github.com/RedRookAI/keep-research-preview/blob/main/WORKFLOW.md

## Project and license

Keep is a Red Rook AI project developed with substantial AI assistance, including Codex. Its original code uses the MIT license; third-party components retain their own terms.

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/licensing.md
