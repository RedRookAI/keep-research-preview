# Maintenance preview — September 10, 2026

Keep 0.0.2-preview.1 (`keep-preview-2026-09-10.1`) is a bounded maintenance
update to the first research preview. It publishes completed corrections and their
regression tests while further audit and development continue. The original
September 9 tag and release assets remain unchanged.

## Included corrections

- Delegated-grant revocation checks the target tenant, preserving legitimate
  management while refusing another tenant's mutation (`KEEP-04B-001`).
- Skill validation requires execution cases and rechecks prior counterexamples.
  A refined candidate's checked content, stored package and approval stay tied
  together (`KEEP-06A-001`, `KEEP-06A-002`, `KEEP-06A-E02`).
- Registry admission and retrieval use content-bound lifecycle state. Static
  catalog storage is explicitly lower-assurance, unchecked replacements cannot
  inherit another version's eligibility, mixed catalogs reconstruct correctly,
  and retirement takes effect live as well as after restart (`KEEP-06A-E01`,
  `KEEP-06B-001`–`003`). E01 records an assurance distinction, not another
  demonstrated execution defect.
- Promotion distinguishes a rejected revision from its incumbent, reports held
  retirement accurately, and persists changes before exposing successful
  promotion through built-in stores (`KEEP-07A-001`–`003`).
- Multi-trace extraction retains declared effects from contributing traces.
  Static foreign-skill translation preserves supported permissions, refuses
  unsupported metadata syntax, and states the limited signature coverage and
  untrusted-key status (`KEEP-06C-001`–`004`). Static storage is not execution.
- A known non-applicable repository edit returns an accurate unsolved result.
  Workspace and original-source delivery outcomes are recorded separately;
  uncertain effects still require reconciliation (`KEEP-03A-001`, `KEEP-03B-E01`).
- Legacy retired skills cannot be revived by admission, bundle import or trusted
  retention merely because their old content binding is unknown. Useful retained
  non-retired skills can pass configured execution checks and become eligible
  again. Regression tests cover refusal, promotion, restart and backup restoration.

Public regression cases are in `test/*_audit.test.ts`, with related validator,
program, registry, evaluator and repository-flow tests. They use synthetic inputs
and controlled resources; passing them is not a real-model learning result.

## Before upgrading saved state

**Stop writers and retain a verified private copy of the complete data directory
before starting this version with existing data. No automatic backup is created.**

The corrected reader preserves valid legacy packages, reuse history and retirement
on load. Old approvals lack a checked-content binding, so unbound entries are not
automatically usable. Revalidation requires a configured execution oracle through
the existing managed API. Successful readmission starts new content-bound counters;
the backup retains the old history. Legacy retired IDs stay retired, including
when their submitted description changes.

The next managed save writes schema v2, which the old preview cannot read. Returning
to old software requires its corresponding old state, and restoring that backup
omits subsequent work. Do not simply change the version number or mix old and new
operational files. Read [the full upgrade guide](skill-registry.md) first.

## Evidence and remaining limits

The [release record](../KEEP_RELEASE.md) identifies the exact public source and
distributed archives and reports checks performed on this candidate. Verification
is builder-administered; separate audit verification of corrections remains distinct.
Historical results remain attached to their original artifacts in
[the evidence record](evidence.md).

This release does not include the later private transport, monetary-accounting,
event-storage, adaptation or isolation correction batches. It does not claim that
all audit findings are resolved. Use synthetic data and isolated test resources;
do not connect production credentials or unrestricted paid services. There is no
claim of universal spending enforcement, production isolation, external-effect
finality, or general coding superiority. Broader native qualification limitations
remain documented in the release record.

The [security studies](security-experiments.md) remain proposed research,
not completed experiments or promised funded outcomes. MIT licensing and required
third-party notices remain in place. No npm-registry publication is part of this
GitHub maintenance release.
