# Security boundaries

Keep is under development. The hosted guided task uses authored responses with real workspace edits, checks and proposal decisions. The self-contained Linux x64 appliance has its own measured browser/startup profile. Fresh live-account generation, production native execution and full-platform qualification remain open.

Current source, hosted and appliance identities:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/qualification/submission-snapshot-2026-11-12.json

<a id="what-the-mechanisms-establish"></a>

## Trust model

- The host administrator and injected provider/adapter code are trusted. In-process adapters share the host boundary.
- Authentication, permissions and tenant checks apply at their implemented entry points. Broader effect-path coverage needs separate verification.
- Durable records retain dispatched and uncertain outcomes. Recovery inspects unresolved work before retrying; local restore leaves external service effects intact.
- Hash-linked audit records bind recorded bytes. Their truth and completeness depend on the recorder and administrator.
- Memory labels and prompt delimiters leave retrieved content untrusted. Execution controls and isolation apply separately.
- Privacy transformations act on detected content. Context, missed secrets, external copies and retained key material remain relevant.
- Monetary reservations cover selected routes. Trace reporting preserves unknown usage/pricing; it is separate from paid admission and provider billing.

Metering details:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/monetary-accounting.md

## Opt-in required project boundary (experimental)

The command runner's `namespaceJail: "required"` mode uses a measured Bubblewrap launcher and kernel namespaces. It refuses unsupported setup. The qualified binary profile is Linux x64 with the expected merged `/usr` layout and exact executable hash.

The operator can select an absolute protected launcher with `KEEP_TEST_JAIL_EXECUTABLE` when `KEEP_TEST_NAMESPACE_JAIL=required`. The default is `/opt/keep/bubblewrap/0.13.0/bwrap`. Both paths require the fixed hash, root ownership, protected ancestry and a non-setuid/nonwritable executable. Repository/model input cannot choose the launcher. `keep doctor` checks its presence and trust; each actual execution also checks setup.

The task receives a read-only system tool tree, its project, explicitly allowed write directories, optional `readOnlyPaths` and fresh temporary directories. Network access defaults off. Unix socket creation is restricted; private stream socketpairs support Node IPC. Other host paths and developer homes stay outside the task view.

`allowNet:true` shares the network namespace. DNS/TLS settings may need operator-approved paths; only numeric-address local connectivity has been exercised. The host kernel and system tools remain trusted.

Use quiescent, operator-owned working directories. Required mode refuses hard links, special files, unprotected writable trees and mounts nested under supplied roots. It scans at most 100,000 entries across all supplied trees within the command deadline; larger or slow scans refuse before entry. The selected root may itself be a mount. The runner preserves operational data when refusing; it leaves link detachment or migration to the operator.

`launcher-confirmed` records the trusted launcher's completed setup/exit protocol. File-size limits are per file, rounded down to KiB; positive limits below 1 KiB refuse, while explicit zero remains zero. Process limits are per user with privilege exceptions. Aggregate memory and total disk need outer resource controls. Default/legacy best-effort behavior and explicit `false` retain their weaker boundaries.

Implementation and launcher recipe:

https://github.com/RedRookAI/keep-research-preview/blob/main/src/infra/required_project_jail.ts

https://github.com/RedRookAI/keep-research-preview/blob/main/tools/bubblewrap/README.txt

### Historical vulnerable archive

The selected non-setuid launcher is Bubblewrap 0.13.0. GHSA-pxhw-h44j-8pfx affects versions below 0.12.0. The historical 0.0.4-preview.1 download remains affected; later source changes leave its published bytes unchanged. Use the release record to identify an artifact's actual dependencies.

https://github.com/containers/bubblewrap/security/advisories/GHSA-pxhw-h44j-8pfx

https://github.com/RedRookAI/keep-research-preview/blob/main/KEEP_RELEASE.md

## Optional native refusal transport: installation prerequisites

The packaged client/supervisor provide a refusal-only development exchange. Workload launch and production isolation authority remain unfinished.

The optional exchange requires an administrator-controlled copy with canonical root-owned ancestry and no group/other write access. `dist/native/linux-x64`, its client and supervisor executables need mode 0555; `keep-native-supervisor.sha256` needs mode 0444. Verify copied bytes against the reviewed archive before and after staging. Ordinary npm installation preserves package contents but leaves this custody step to the administrator.

These ownership/mode checks are relative to the namespace and trusted administrator. Retain bounded diagnostics for stream failures; a local failure can leave peer receipt uncertain.

<a id="public-test-material"></a>

## Test fixtures

Security tests contain synthetic credential-shaped strings, rejection markers and untrusted input. Vendored cryptography retains upstream example keys and test vectors with their notices. Inspect provenance before treating a key-shaped match as a fixture. Published fixtures and expected answers are exposed material for future evaluations.

<a id="reporting-a-vulnerability"></a>

## Report a vulnerability

Open **Security → Advisories → Report a vulnerability** in this repository. Private vulnerability reporting is enabled.

https://github.com/RedRookAI/keep-research-preview/security/advisories

Include the artifact/version, environment, synthetic reproducer, expected behavior and observed result. Keep credentials, private repositories, customer data and unredacted traces out of public issues. Test only deployments you are authorized to assess.
