# Skill catalog, admission, and preview-data recovery

A stored skill package is available for inspection. That alone does not make it
eligible for task retrieval. Managed admission records the hash of the skill
content that passed the configured gate. Retrieval in the composed runtime checks
that binding, the current retirement state, and the canary state. These checks do
not turn an envelope-only gate into execution evidence or establish improvement
over a no-skill baseline.

The install response includes an `assessment` with the gate's verdict, the submitted
`inputContentHash`, and the accepted `contentHash`. Without an execution oracle,
the public install path reports `envelope-checked`; it does not run typed examples
or task cases. With validation configured, a refined candidate is repackaged under
its own content hash and checked against the receiver's policy before admission.
The requested skill ID remains unchanged. Origin is still a declared source, not
an authenticated signature on the receiver's revised content.

Trusted custom gates that refine a candidate must return it as `checkedSkill`.
Omitting that field means the unchanged input passed the named check. Installation
detaches and freezes input/output objects, so callbacks should return revisions
rather than mutate the supplied object. Bundle preflight keeps the checked versions
and refuses the entire bundle if a later checked version violates receiver policy.
This does not guarantee atomic recovery from every storage failure during commit.

Replacing catalog content under an existing ID does not transfer the previous
version's admission to it. Until the replacement is explicitly admitted, its
status is `content-changed`, and neither it nor a stale cached copy is offered by
managed retrieval. Catalog-only entries can coexist with managed entries in the
same snapshot without preventing restart. A catalog install alone is not durable
managed admission: catalog contents reach this snapshot only when a managed save
occurs. Retirement keeps the current package and its retirement record while
excluding it from current retrieval.

The registry stores one current lifecycle per ID, not a complete version archive.
Checked admission of different content under that ID starts a new lifecycle,
including clearing the former version's retirement. Keep a private backup if that
former record is needed. Identical-content re-admission retains its retirement.
The trusted `trackValidated` integration port relies on its caller having checked
the supplied candidate; it does not run that check itself. Canary reactivation and
promotion outcomes are separate from the managed binding and must agree before
the replacement can be described as live.

## Promotion and failed persistence

Managed changes are prepared in a detached snapshot. The configured persistence
port saves it before the built-in catalog and lifecycle expose the change. The
composed evaluator then supplies retrieval and activates the version-bound canary;
its promotion notification follows those operations. A rejected different-content
candidate leaves the accepted incumbent alone. Degradation of the exact admitted
content retires that content before reporting rollback. Identical retired content
receives `held-retired`, and repeated `goLive` returns the existing state with an
`unchanged` transition. A checked different revision can start a new canary.

Equivalent candidates receive `merged`, with scores attached to the evaluated
`skill` and the retained canonical content identified separately as `mergedInto`.
The duplicate does not first become live. A content or retirement change while
validation/evaluation is running requires evaluation against the new state;
stale evidence cannot overwrite that intervening decision.

The file persistence implementation writes a temporary snapshot and renames it.
A failed promotion write or rename leaves the prior live state unchanged and emits no
promotion notice. Inspect and resolve the storage problem before retrying; do not
install the leftover `.tmp` file as a committed snapshot. The reader never adopts
that temporary file. A high-impact retry reruns execution and can reuse the cleared
criticism only for the same failed-retention candidate, cases, scores and admission
state. That retry cache is local and transient, not a persisted approval.

Custom persistence or catalog callbacks can fail after changing their own state.
Such failures report an error and fence managed eligibility and mutation as
`reconstruction-required`. A failed withdrawal also fences live eligibility even
when its retirement could not be saved. Preserve and reconcile the actual stored
state before reconstruction; restarting alone does not prove an unsaved withdrawal
became durable. Custom ports and direct trusted canary calls must honor their
coordination contracts. Notifications are best-effort, not an exactly-once queue.
This implementation does not establish power-loss durability, concurrent-process
writer safety, or a transaction spanning external services.

## Static foreign-skill inspection

`/skill/adopt-openclaw` proposes a specification by default. Boolean
`acknowledgeRisk: true` permits static catalog translation through an envelope
screen, not execution validation, measured improvement, or activation. Both the
proposal and translated envelope use the same declared-effect mapping.
`file-write` carries a `workspace:write` requirement; declared binaries carry
`sandbox:execute`. These fields never mint grants. Original permission strings
remain tagged declarations, and unknown mappings appear in `unsupported`.
The package still has no executable steps. Tools and environment names are
metadata, not permission grants or authenticated descriptions of actual behavior.

The supported SKILL.md subset is fenced top-level scalars, block string lists,
JSON string arrays, and inline strict-JSON metadata. For example,
`permissions: ["file-write"]` or a block list is supported;
`permissions: [file-write]` returns `unsupported-input-language` rather than
silently losing the permission. `allowed-tools: Read Write` is retained as one
verbatim scalar declaration, not parsed executable tool rules. Multiline
metadata, YAML aliases/tags, duplicate fields/JSON keys, mixed-type lists, and
ill-typed consumed fields are refused. Inline metadata reuses Keep's strict JSON
reader: integers only, bounded nesting, and well-formed Unicode. This is not a
complete YAML, JSON5, AgentSkills, or OpenClaw runtime implementation.

The legacy custom Ed25519 payload is exactly `name + "\n" + description + "\n" +
version`. Single-line intent fields are required. `verified-intent-fields`
replaces the former ambiguous `verified` status; `invalid`, `unsigned`, and
`not-checked` are distinct. `signatureInfo` states coverage and the fingerprint
of a parseable embedded SPKI key. That key remains untrusted. The `coveredFields`
list describes the scheme's payload, not a successful check; signature status
reports validity. Body, permissions,
triggers and other metadata are not covered; replacing them can leave the
three-field signature valid. `sourceSha256` identifies the **current input** and
is itself unsigned—it does not detect modification without a trusted prior value.
Legacy object inputs use their JSON.stringify representation, not original file
bytes. Static packages retain these scope/status/digest/fingerprint records as
non-authorizing provenance. No trusted-signer service or new signing standard is
implied. Existing preview packages cannot acquire this missing provenance by
restarting; inspect and translate the original source again where needed.

For native trajectory extraction, effects from all occurrences of retained
actions are combined before screening. The returned `extraction` record names
retained actions, omitted source-step count, distinct supplied solve IDs, and
whether concrete targets collapsed into the same parameter slot. This is a
common-action pattern, not a semantic reconstruction or a screen of omitted
actions. Repeating one solve ID does not add corroboration; distinct supplied IDs
still do not establish independent evaluation. Required authority conservatively
unions declarations from all successful source traces, including omitted steps.
The envelope has shared named parameters, so `read input.mjs` and
`write output.mjs` both becoming `{file}` loses a distinct-target relation even
though their action names differ; `collapsedTargetSlots` flags that limitation.

## Upgrading data from the September 9 research preview

The original preview writes registry snapshot schema version 1. That format does
not record which content earned each lifecycle record. Because the preview also
allowed same-ID catalog replacement, a v1 snapshot cannot reliably distinguish a
previously checked skill from content that inherited another version's state.

The corrected reader retains valid v1 packages, reuse history, and retirement
records, but marks their existing lifecycle bindings `legacy-unverified`. They
are not automatically activated. Packages without lifecycle records are
`catalog-only`. Loading does not rewrite the file. The next ordinary managed save
writes schema version 2, keeping unresolved legacy bindings explicitly null.

Before using a newer build with existing state, retain a private backup of that
state. Inspect each intended skill and explicitly submit its exact package through
the managed registry's ordinary `add` validation path with the appropriate
execution oracle and, where applicable, typed-program implementations. A public
catalog install, restarting, or manually filling in a hash is not revalidation.
Re-admission starts version-specific use history where the earlier content binding
was unknown: use/reward counters start at zero and the new lifecycle starts at the
accepted package's publication time. The original backup retains the old history;
it is not silently credited to the newly checked content. There is no built-in
archive of every former lifecycle.

A legacy retirement remains effective even if submitted content or metadata changes.
Ordinary admission, bundle import, and trusted retention do not reactivate that ID.
Its status is `retired`; its missing content binding still remains null in the saved
record. There is no administrative unretire operation in this preview. A deliberately
revised replacement must use a new ID and pass the ordinary checks; integrations
referring to the old ID must be updated deliberately. Permission-grant revocation
is a separate control and is not undone by skill checking. For already content-bound
v2 records, the documented checked-new-revision policy above remains unchanged.

Managed `add` and bundle import return `held-legacy-retired` for this local-state
hold; it does not label the submitted content unsafe. A bundle containing such an
ID is refused in full, including otherwise acceptable entries. The sender must
omit that entry or deliberately export an appropriately checked new-ID replacement;
the preview does not offer a skip-on-import switch. Do not retry unchanged bundles
or parse the explanatory `detail` as an API contract.

An explicit **static catalog install** remains separate: it can replace the stored
package under this ID without clearing retirement or granting retrieval. A later
managed save can persist that catalog replacement. This registry is not a version
archive; recover the former body from the pre-upgrade backup if needed. Neither the
`retired` label nor a successful catalog response proves that the currently stored
body is the one to which the unknown legacy retirement originally applied.

### Revalidate a retained, non-retired skill

This is a trusted local integration operation, not a public revalidation endpoint
or a one-click migration. Configure `composeKeep` with your task-specific
`skillOracle`, any required `skillPrograms`, and appropriate `skillImportAuthorities`
first. The oracle must execute relevant cases and judge actual outcomes. Keep cannot
infer a valid execution test for arbitrary old procedures from their description.
With that configured `app`, submit the retained package itself:

~~~js
const pkg = app.registryStore.get(skillId);
if (!pkg) throw new Error("Skill is not in this catalog");
const result = await app.managedSkillRegistry.add(pkg);
if (!result.ok) throw new Error(result.detail);
console.log(result.assessment); // Submitted and checked content identities.
console.log(app.managedSkillRegistry.admissionStatus(skillId));
// Check the intended task's retrieval too: admission is not universal activation.
~~~

Without an execution oracle the composed managed path refuses admission. Public
catalog installation alone does not substitute for this operation. A failing check
leaves the previous persisted package and lifecycle unchanged. A refining check can
produce different content; inspect both hashes instead of treating that as exact
retained-content revalidation.

### Back up before opening existing state with the new build

Stop writers and make a private copy of the complete configured data directory
before starting the new version. Keep that copy outside the running data directory,
protect its credentials and private contents, and verify the copied files. Loading
alone preserves the registry file, but the first ordinary managed save replaces it
with v2. **Keep does not create an automatic pre-upgrade backup.** Do not wait for a
conversion prompt. Test upgrade and recovery on disposable copies first.

Restoring an older backup is a point-in-time recovery: later skills, revalidations,
retirements, outcomes, and other saved work are absent. Preserve the newer directory
separately before recovery, and reconcile any consequential external actions before
resuming work. Do not mix old registry files into newer operational state and assume
the combination is consistent. The regression test demonstrates exact registry-byte
restoration and loss of a later synthetic addition, not universal rollback of all
Keep state or external effects.

Trusted integrations can query `managedSkillRegistry.admissionStatus(id)` to
distinguish `missing`, `catalog-only`, `legacy-unverified`, `content-changed`,
`retired`, `admitted`, and `reconstruction-required`. An `admitted` result describes the managed binding; the
canary and other retrieval conditions still apply.

Malformed packages, digest mismatches, duplicate records, and lifecycle records
without a corresponding package remain errors. The reader leaves those input
files unchanged for investigation; it does not delete them or reset the registry.
Version 2 is not readable by the original preview. If reverting to that build,
restore its matching private state backup rather than editing the new snapshot's
version number.

The version boundary is deliberate: the old reader has no checked-content binding
semantics. Keeping the old version label would make it accept records while ignoring
their new restrictions. A sidecar or dual-format writer would add another state
consistency problem without teaching the old runtime to enforce those restrictions.

This is a targeted data-compatibility correction. It does not qualify every skill
generation, refinement, evaluation, promotion, or storage-failure path. Consult
the evidence for the particular build and workflow being used.
