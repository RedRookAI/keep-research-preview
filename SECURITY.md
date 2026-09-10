# Security boundary and disclosure

Keep is an incomplete research platform. It is not currently qualified for
unattended consequential production use. The supported first demonstration uses
synthetic data and a local test outbox, with no live model or external service.

## What the mechanisms establish

- Authorization applies at specific entry points; an in-process adapter is trusted
  host code, not automatically an isolated adversary.
- The reference deployment reports missing or detection-only controls explicitly.
  Available namespaces, Landlock or virtualization do not establish active isolation.
- Durable dispatch/accounting records preserve some uncertain outcomes. They do
  not promise exactly-once effects for arbitrary remote services.
- A hash-linked audit trail does not prove the truth of events, absence of omitted
  events, or independence of the observer. A same-host witness is not an outside auditor.
- Memory/skill labels and prompt delimiters do not make untrusted content safe.
  Configured execution checks and actual isolation remain necessary.
- Privacy transformations reduce some exposure; they do not guarantee anonymity,
  complete secret detection, or deletion from external providers.
- Paid-usage metering is incomplete across routes. Do not rely on it as a universal
  billing ceiling or attach unrestricted paid credentials.

See [monetary accounting](docs/monetary-accounting.md) for durable reservations,
legacy-state handling and incomplete coverage.

Inspect [enforcement profiles](src/platform/enforcement_profile.ts) and the
[demonstration limits](docs/research-preview.md#interpreting-the-result) and
[evidence record](docs/evidence.md) for the exact boundaries.
Run hostile code only in an appropriately isolated, explicitly authorized environment.
Do not expose a gateway publicly merely because local authentication tests pass.

## Opt-in required project boundary (experimental)

The command runner's `namespaceJail: "required"` mode uses the existing Bubblewrap
launcher and kernel namespaces. It refuses unsupported setup rather than falling
back to an unrestricted command. Its current qualified-binary configuration is
Linux x64 with the expected merged `/usr` layout and the exact launcher identity
checked in [the implementation](src/infra/required_project_jail.ts). Other binaries
or operating arrangements require qualification; a version string is insufficient.

The task receives a read-only system tool tree, its project and explicitly allowed
write directories, optional `readOnlyPaths`, and fresh temporary directories.
Network access is off unless `allowNet: true` is explicitly selected. Unix socket
creation is restricted, while private stream socketpairs support ordinary Node IPC.
Developer home directories and other host paths are not automatically exposed.
Network opt-in shares the network namespace; it does not supply resolver settings
or certificate authorities. DNS/TLS may need operator-approved configuration in
explicit `readOnlyPaths` directories. Only local numeric-address connectivity has
been exercised in the current network checks.

Supply quiescent, operator-owned working directories. Required mode refuses shared
file inodes (hard links), special files, unprotected writable trees and nested host
mounts in supplied roots. It does not detach links, copy or migrate operational
data. The host kernel, system tools and absence of concurrent host-side changes
remain trusted; directory scanning does not establish global exclusive ownership.
An explicitly selected root may itself be a mounted volume; mounts below it are
refused. Admission scans at most 100,000 entries across the supplied read/write
trees, including dependencies, within the command's existing time limit. Larger
trees or slow scans are refused before task entry, not partially admitted.

`launcher-confirmed` records the trusted launcher's completed setup/exit protocol,
not independent witnessing, a VM boundary or unrestricted production readiness.
File-size limits are per file and rounded down to KiB; positive limits below one
KiB are refused, while explicit zero remains zero. These are not a total disk
quota. Process limits are per user and have privilege exceptions. This runner does
not impose an aggregate memory ceiling. Use separately qualified outer resource
controls for hostile workloads. Legacy `true`/default best-effort and explicit
`false` behavior remain available and carry their weaker observations.

Builder tests cover the selected Linux layout and useful-work/refusal controls.
The pinned Bubblewrap version is affected by [GHSA-pxhw-h44j-8pfx](https://github.com/containers/bubblewrap/security/advisories/GHSA-pxhw-h44j-8pfx).
The tested fixed layout avoids its setup-time directory-creation precondition; this
is not a patched dependency or general clearance of other layouts. Changing the
launcher or layout requires fresh qualification. The separate native build-tool
launcher has source inspection only for this advisory.

## Optional native refusal transport: installation prerequisites

The packaged native client/supervisor currently provide a refusal-only development
exchange. They do not launch workloads or grant production isolation authority.
The introductory recovery demonstration does not require this transport.

An ordinary npm installation preserves package contents but does not establish
the native client's required custody. For this optional exchange, a separate
administrator-controlled copy must have canonical, root-owned directory ancestry
with no group/other write access. Its `dist/native/linux-x64` directory and client/
supervisor executables must have mode `0555`; `keep-native-supervisor.sha256`
must have mode `0444`. Verify all copied file bytes against the reviewed archive
before and after staging. Do not run npm lifecycle scripts as root to establish
these permissions, or change an existing application's data to satisfy them.

These are namespace-relative ownership and mode checks, not protection from a
host administrator, proof of a read-only filesystem, or adversarial attestation
between same-user processes. An ordinary install that fails these checks must
remain refused. Stream failures retain bounded client diagnostics; neither an
error message nor a failed write proves whether a peer received an operation.

## Public test material

Security tests intentionally contain synthetic credential-shaped strings, rejection
markers and untrusted inputs. Vendored cryptography packages also retain upstream
example keys and test vectors with their source notices. These are development
fixtures, not credentials to use in an operational deployment. Do not substitute a
real secret into a public reproducer or assume that a key-shaped match is harmless
without inspecting its provenance and use.

Published fixtures and expected answers are exposed development material. A future
research comparison must not describe them as unseen held-out tasks. Passing these
tests does not establish complete secret detection, independent evaluation or
protection against every untrusted input.

## Reporting a vulnerability

GitHub's built-in private vulnerability reporting is enabled for this public
preview. Open this repository's **Security**
tab, select **Advisories**, then **Report a vulnerability** to send a private report.

The enabled setting was verified through GitHub's API, and the public Advisories
page displays the reporting link. Maintainer notification delivery has not yet been
verified. No response deadline, bounty, dedicated security team or separate email
address is promised. Do not use public issues to transmit sensitive reports.

Do not post credentials, private repository contents, customer data, authentication
headers or unredacted traces in public issues. Use the private form when available;
provide the exact artifact/version, environment, minimal synthetic reproducer,
expected outcome and observed result. Distinguish a static suspicion from a
reproduced effect. Never test against another person's deployment without permission.

Maintainer configuration follows GitHub's
[private vulnerability reporting guidance](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository).
