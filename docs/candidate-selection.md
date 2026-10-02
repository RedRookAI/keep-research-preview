# Candidate selection

Keep exposes optional library methods for sampling candidate repairs, comparing
them with generated tests, and trying progressively more expensive configurations.
These methods select proposals. They do not themselves grant permission to merge
or deliver a change, and are not automatically used by every project route.

## Checked content and test evidence

Selection captures an owned, deeply immutable copy of each sampler result before
checking it. The workspace wrapper captures before releasing its lease. Generated
test inputs and descriptions are captured too, so callbacks cannot change the
retained candidate or the meaning of an earlier test observation through aliases.
The returned winner is a copy, not the sampler's original object.

Sampler results, generated tests, `verify` verdicts and `measureTaskFidelity`
measurements must be inert ordinary data: plain objects, dense arrays, strings,
finite numbers, booleans, null and optional undefined fields. Accessors, functions,
class instances, cyclic objects and shared mutable buffers are rejected. Capture
limits are 64 nested levels below the root, 100,000 values and 16 MiB of string
values. Capture checks run when each output arrives, so rejection can occur after
sampling has consumed resources. A rejected capture fails the operation and still
runs cleanup. Convert custom class-backed results to plain
records before returning them; do not remove evidence fields to obtain a pass.

The generated-selection result includes candidate JSON-content digests by sample
index. Undefined optional fields and absent fields have the same JSON identity.
Digests identify contents, not truthful execution, independent verification or
semantic correctness. Genuine process-local canonical-edit attestations survive
an exact owned copy; copying serialized records cannot create that attestation.

Generators and executors remain trusted host code and must test the supplied exact
candidate in an appropriately isolated environment. A generated test that all
candidates fail may expose a shared bug. Pass-profile clustering does not establish
test validity or general behavioral equivalence. Preserve failures for inspection.

## Workspaces and failure handling

Every sample, including a single candidate, receives an execution identity and a
resolution identity. Custom workspace factories must scope allocations to both;
execution identifiers alone are only unique within a resolution. The built-in
snapshot factory gives candidates separate in-memory trees from a shared captured
base. This is not an operating-system sandbox or a disk-backed worktree factory.

On a worker failure, the selector stops assigning new samples, waits for those
already started, then finishes the resolution. Cleanup runs once after the workers
have settled. Multiple failures are returned as AggregateError with the first
observed failure as its cause. If cleanup also fails, the outer AggregateError
contains the worker failure (which may itself be an AggregateError) and the cleanup
failure, preserving those distinct boundaries. A single failure retains its original identity.
The sampler contract must provide finite work; these callbacks cannot be forcibly
cancelled by Promise.all or by this library.

Workspace leases finish before generated tests. An executor needing workspace
contents must reconstruct the captured patch on the matching base; it must not
assume a custom lease remains usable after release.

## Cascades

A tier requesting generated tests requires both generator and executor. Missing
configuration rejects before any tier runs, even if complexity routing would have
skipped that tier. A single cleared candidate needs no differential comparison.
Ordinary tiers retain their normal patch checks. On budget exhaustion or a later
failed tier, the retained winner keeps its own behavioral-disagreement flag.

Budget inputs here are estimated costs and a supplied affordability/accounting
port. They are not by themselves a universal spending ceiling. Deployment-specific
model metering and resource limits must be qualified separately.
