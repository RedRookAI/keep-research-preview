# Keep

Keep is a self-hosted platform for AI agents working on ongoing projects. It combines
a native execution runtime with persistent knowledge, reusable procedures, and
controls for permissions, acceptance, and recovery. Red Rook AI is developing Keep
for individual operators and organizations coordinating several agents.

The goal is to let agents take on longer assignments and improve through experience,
while giving their owners practical control over the work. Software development is
the most developed workflow today. Keep can inspect a repository, obtain a
model-proposed change, run checks in a work area, and apply the configured acceptance
and merge policy.

Keep is under active development. The first public research preview includes the
implementation and a Linux x64 demonstration of resource accounting and recovery
when an operation's response is lost. The demonstration requires no model account
or paid service.

Download [maintenance preview 2026-09-10.1](https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-09-10.1).
The [release record](KEEP_RELEASE.md) identifies the reviewed source, prepared
archives, checksums, and qualification results.

The [maintenance notes](docs/maintenance-2026-09-10.md) describe the corrections
and remaining limits. **Before upgrading existing data, read the
[skill-registry upgrade instructions](docs/skill-registry.md#upgrading-data-from-the-september-9-research-preview)
and retain a private offline backup.**

Start with the [preview guide](docs/research-preview.md) to install the package and
run the experiment. The [research overview](docs/research.md) describes the wider
platform and the questions being investigated.

**Use the preview with synthetic data and isolated test resources. It is not ready
for unattended production use.** Keep production credentials and unrestricted paid
resources out of the introductory setup; see [Security](SECURITY.md).

## Start with the no-key experiment

The demonstration compares a durable local outbox with Keep's resource accounting.
It injects failed acknowledgments, restarts processes and tests reused dispatch
permits. Benign controls exercise work that should still proceed.

The preview guide identifies the supported environment, current release record,
commands and [known test limitations](docs/evidence.md#known-test-status). It also explains how to inspect the outbox
instead of relying only on Keep's success message.

## Build and inspect

The first supported introductory configuration is Linux x64 with Node.js 22.23.2
and npm 10.9.8. Building native code also needs the pinned Rust toolchain and host
C build tools described in the preview guide. A binary-package consumer does not
need Rust.

From a source checkout:

~~~sh
npm ci
npm run test:fast
npm run test:notices
~~~

These commands install locked dependencies, typecheck TypeScript and check notices;
they do not execute the behavioral suite. See [Contributing](WORKFLOW.md) for the
build and test commands and the preview guide for installed-demo instructions.

## Explore the implementation

| Area | Starting points |
| --- | --- |
| Coding | [Native observation/proposal loop](src/solve/edit_planner.ts), [governed merge and revert](src/solve/governed_local_merge.ts) |
| Memory | [Source-linked task context](src/memory/task_context.ts), [semantic retrieval and retention configuration](docs/semantic-memory.md) |
| Skills | [Distillation](src/loop/skill_distiller.ts), [comparative evaluation](src/loop/skill_evaluator.ts), [registry lifecycle](src/registry/skill_registry.ts) |
| Fleet | [Joint admission](src/fleet/fleet_gate.ts), [durable resource and effect lifecycle](src/fleet/fleet_lifecycle.ts) |
| Deployment controls | [Enforcement profiles](src/platform/enforcement_profile.ts), [capability/evidence graph](src/graph/capability_graph_v2.ts) |
| Audit | [Pre-effect witnessing](src/witness/pre_effect_witness.ts), [evidence export](src/witness/witness_export.ts) |
| Authority | [Delegation](src/identity/delegation_registry.ts), [merge decisions](src/oversight/merge_authority.ts) |

Keep supports native execution and has CLI, gateway, client and integration
interfaces. Qualification differs by route; these interfaces are not a promise of
compatibility with every provider or external coding agent. OpenClaw skill intake
currently handles static intent/specification material. Signed desktop/mobile
applications are not part of this preview.

## Read further

- [Preview and installation](docs/research-preview.md)
- [Research at Keep](docs/research.md)
- [Planned security experiments](docs/security-experiments.md)
- [Results, artifacts and known test status](docs/evidence.md)
- [Contributing and tests](WORKFLOW.md)
- [Security and private reporting](SECURITY.md)
- [Licensing and attribution](docs/licensing.md)
- [Semantic memory configuration](docs/semantic-memory.md)
