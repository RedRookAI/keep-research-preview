# Local qualification outputs

Local qualification runners write their reports here. Reports bind actual inputs
and results; their existence does not confer runtime, release or deployment authority.
The public checkpoint does not include private operator records or raw fixture payloads.

`tools/qualify_project_jail.mjs` requires a prepared namespace environment and the
exact reviewed launcher. `tools/qualify_exact_revision.mjs` refuses direct shared-host
execution and requires a prepared mapped fixture with actual outer resource limits.
Neither runner prepares a shared host or boots a VM. Read [the workflow](../../WORKFLOW.md)
and [public checkpoint evidence](../evidence.md#october-4-public-source-checkpoint).

The installed backup journey additionally requires a matching locally qualified
archive record. Missing or mismatched evidence must refuse; do not invent qualification
metadata to make a journey pass.
