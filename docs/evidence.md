# Evidence and limitations

This page records what was exercised, on which artifacts, and within which
boundaries. The [security research brief](security-experiments.md) explains the proposed studies;
the [preview guide](research-preview.md) explains how to run the first experiment.

## Current release record

Use the companion `KEEP_RELEASE.md` supplied alongside the source and package
archives for the current candidate's identities and actual check results. It is
outside the archives so its checksum record does not refer to itself. Results
below remain attached to their original source and package, even when the
implementation is retained in a later release.

All results here were administered by the development session. A repository test
or local effect sink is an outcome checker separate from the model; it is not
outside administration. No genuinely outside replication is recorded.

## Starting results

### Native repository repair

On September 7, 2026, installed runtime
`f1a614f72db9c4e019b1ee7487dcba13d70e2568`, package SHA256
`2f8a36f3138fb40da7e0a9059b774a9327d8b5f86fc0412e7049852db06c9b4f`,
completed one synthetic owner-scoped repair with Cohere's
`cohere/north-mini-code:free` through OpenRouter. Two actual HTTP attempts produced
an approval-required proposal that passed a separately defined Node repository
test. Original source, configuration, and tests remained unchanged. A fresh
process read the result without another inference request.

The acceptance driver was recorded at
`499371ef74b9b549d8ebc1788061e980cbe2f55b`, separately from the installed runtime.
An initial driver guard rejected the configured token limit before any HTTP call;
that failed attempt was retained. This is one authored task, not general coding
performance or enterprise-model qualification. The acceptance request cap is not
a comprehensive product billing ceiling.

Runnable harness source: [native provider journey](../acceptance/installed_sg04_live_provider_journey.mjs).
This model-backed historical harness requires separately authorized model access;
it is not the no-key introductory experiment.

### Governed repository workflow

The September 7 installed fixture checkpoint at
`0966f5963393148b2f88a2354f4d6d5eb1f779a0`, package SHA256
`a5bbfdfad2e492de187bfa0368ac914472a85e8374902929f8fe09a20c41b600`,
records passing personal and organization fixture journeys. The repository
journeys exercise proposed work, unauthorized mutation refusal, acceptance,
merge, runtime reconstruction, and revert, with repository state as the checker.
Separate recovery cases exercise fresh processes. This historical consumer used an
offline, scripts-disabled installation; it is not the current ordinary-install proof.

Harnesses: [personal journey](../acceptance/installed_n1_golden_journey.test.mjs)
and [organization journey](../acceptance/installed_enterprise_golden_journey.test.mjs).
These use controlled model behavior and test authority. They do not establish
production organizational identity, broad coding quality, or reduced operator
effort. This checkpoint's broader historical qualification does not override the
later failures listed below.

#### Reading repository outcomes in the corrected runtime

`GET /project` and `GET /projects` expose an additive `repository` summary.
Its `observation: "last-recorded"` field matters: this is a projection of the
journal, not a fresh inspection of Git or a delivery guarantee. `workspace`
records the merge or inverse completed in Keep's workspace. `source.merge` and
`source.revert` separately record delivery to the configured original repository.
Their status can be `landed`, `reverted`, `refused`, or `unknown`. A refused
attempt does not undo prior work; missing results, interrupted attempts and
unresolved execution errors remain unknown. Older workspace-only history has no
inferred source success. Existing journals are read without rewriting history.

`latestDecision` (also the list's `decision`) identifies the latest recorded
request outcome, separately from completed workspace work. Source-attempt entries
use `source_delivery.<merge|revert>.<status>`; `pending` means no final attempt
result has been recorded. `local_merge.reverted` is the summary label for the
workspace's `local_merge.revert_terminal` event. Reporting reasons are bounded
to 500 characters. These reporting entries never authorize replay.
Source-operation responses include `sourceDelivery.recorded`; a false value
warns that reporting persistence could not be confirmed, even if Git delivery
was observed to succeed. Resolve that journal problem before relying on the
record or retrying. No failed log write triggers an automatic Git retry or undo.

An initial non-applicable edit returns a retained unsolved result rather than an
uncertain-effect obstruction. Its apply record says `classification:
"non-applicable"` and `effect: "not-attempted"`; a matched prefix is held, not
partially applied. Actual unexpected exceptions still require reconciliation.
These are corrected-runtime contracts; historical release results above and
below retain their original artifact identities.

### Coding with corrected memory

On September 8, source
`808464fda753b7eb51721dcd11efeaaea785b018`, package SHA256
`25f473dc1e34b1614a1484f1791df2bec2b047c6b2550d9f2f0e1c1c19d3ff58`,
passed two installed real-model temporal-memory tasks: personal and signed
organization-fixture authority. Each used three native planning calls, including
a model-selected memory read, and passed separately defined repository checks
while leaving the source and tests unchanged. The earlier blocked pair made zero
model calls and remains a separate failed diagnostic.

The model transport used a controlled local Claude CLI bridge to Keep's native loop,
not the external agent's full coding workflow. Reported model usage included
`claude-opus-5` and auxiliary `claude-haiku-4-5-20251001` activity; these are the
recorded service identifiers, not an assertion about current model availability.
Both tasks belong to one authored family involving historical and corrected
settings. The package reused six previously built native files; this was not a
fresh-native portability result. Supplied passages, selected actions, and repository
outcomes were observed; internal causal reliance and broad learning transfer were
not established. Fixture authority is not a production identity provider.

Implementation: [task context](../src/memory/task_context.ts).
The historical raw development records are not included wholesale because they
contain private operational context; this is a scoped public result summary.

### Uncertain outcomes and dispatch permits

The [introductory harness](../acceptance/installed_sg32_resources.mjs) compares
Keep's accounting with a durable, fsynced local outbox. It covers 16 accounting
cases and 8 single-entry cases across personal and injected-tenant configurations.
An effect followed by a lost acknowledgment retains an obligation; excess work
is held across fresh-process restart. Pre-invocation refusal and available-capacity
controls permit useful work. Concurrent and restarted reuse of a dispatch permit
must not enter the adapter twice.

Use the current release record for the actual rerun result. The sink is trusted
local test infrastructure. Missing local rows in a zero-effect control are not
proof that a remote operation can never commit. These schedules do not establish
abrupt in-flight crash recovery, arbitrary service finality, or the proposed combined
memory/authority-revocation property.

## Known test status

The current record reports the introductory demonstration separately from the wider
experimental suite. On historical source `63cbf80`, the broader portable run had
**4,497 passes and 11 failures**; its release/security phase did not run. These counts
have not been refreshed on the current candidate.

| Historical finding | What is established and what remains unresolved |
| --- | --- |
| Two ownership-change tests and one KVM-presence assumption | The diagnostic single-UID namespace could not represent the requested owners, and its exposed filesystem did not satisfy the KVM assumption. These are identified environment prerequisites, not isolation evidence. |
| Six repository-flow cases | All initially encountered absent workspace paths. Supplying that prerequisite made one pass; five still failed, with goal-check protocol refusals among the results. They are not classified as environment-only or fixed. |
| One solver-result case | Expected result data was missing. Its broader workflow relevance remains unresolved; the introductory accounting demo does not exercise that solver path. |
| One automatic-retry expectation | The stale CLI fixture was corrected to expect reconciliation after uncertain dispatch, with targeted passing checks. That does not qualify the other failures or the whole suite. |

A passing accounting demonstration does not qualify general coding, solver or
repository-recovery workflows. Earlier installed coding results are bounded historical
evidence, not a current broad-suite pass. Relevant failures must be resolved before
making stronger claims about those paths; publishing their experimental source does
not require pretending those claims have already been earned.


## Reading implementation claims

Implemented mechanisms, component tests, installed synthetic workflows, and
installed real-model participation answer different questions. Research sections
describe comparisons still to be performed, not measured advantages.

Skill syntax, intake, execution permission, held-out usefulness, promotion, and
continued eligibility are separate gates. A replacement specification is not yet a
tested executable replacement. Weight-training orchestration has no qualified
end-to-end training result. Configurable model transport does not qualify every
provider or a complete external coding agent.

Enforcement profiles describe specific deployment evidence. Available kernel
features or declared containment do not prove an active isolation boundary.
Hash integrity supports consistency under the verifier's trust assumptions; it
does not establish complete observation or semantic truth. See [Security](../SECURITY.md)
for operational restrictions, including incomplete paid-usage metering.

Public fixtures and expected answers are exposed development material. Future
studies must separate them from genuinely held-out tasks, retain negative outcomes,
and distinguish independent execution from independent administration.

## Evidence history

Earlier runs below retain their own identities and limitations. They do not identify
the current distribution; use `KEEP_RELEASE.md` for that.

### Historical development evidence — source 63cbf80

This is a superseded development artifact, not the current release candidate.
The accompanying candidate handoff records the prepared artifact's exact bytes,
environment and results separately; these historical results do not qualify later
changes merely because they share a date.

Source `63cbf8065f7ad5d32d9026466986f907697bdd16` built from a
selected snapshot with digest
`164579a6c75e1183a673e7e5c3a1e9d36c1d87e96f89084c8fba09a8aacfb073`.
Its 6,225,631-byte package (2,077 entries) has SHA-256
`258708115d67abad5c2d3b0fd17efba60ad83214e7c9f66a97c6c0575a051784`.
It passed scripts-enabled, fresh-cache installation and the 16 accounting plus
8 single-entry cases in a separately installed consumer. The build compiled native
outputs from source using the previously acquired pinned Rust toolchain, mounted
read-only at a different path. It did not reacquire that toolchain. The consumer
had neither the source checkout nor Rust visible; the demonstration had no external
network and made no model calls. Direct sink readback agreed with the recorded
capacity and uncertainty outcomes. This remains a same-host, builder-administered
result, not outside replication or publication clearance.

The following earlier result additionally exercised fresh toolchain acquisition:

Source `a5dacc3ecda5b8cfbd334fc1add264271cb5580d` produced a reviewed-selection
candidate (content clearance was incomplete at that checkpoint) with snapshot digest
`548d16022e0846d701d042531da4fed68526b829b711cc9c733360bde10b4990`.
The resulting 6,222,737-byte package has SHA-256
`0649c2aacdb85f1cce94b8cf26b0d55838cb50a36f36708786e6406de711ac08`.

Scripts-enabled dependency installation used empty npm caches; the selected Rust
toolchain was freshly obtained and native binaries rebuilt. A separate binary-package
consumer, without the source checkout or Rust compiler visible, passed 16 accounting
and 8 single-entry cases using 48 fresh child processes. The demonstration was
network-disabled and made no model calls. Direct durable sink observations included
one effect and one unresolved obligation against capacity one, with excess work held;
capacity-two and genuine pre-invocation-refusal controls permitted useful work.

Both environments still used the maintainer's host/kernel and system tools. This is
builder-administered local isolation, not genuinely outside replication. This exact
archive is historical development evidence, not a published release; later source
or documentation changes have not automatically been rerun. Full-suite and broad
platform/provider qualification are separate from these 24 cases. The final preview
must identify its own bytes, environment, results and limitations.
