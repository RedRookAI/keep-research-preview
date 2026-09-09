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

Inspect [enforcement profiles](src/platform/enforcement_profile.ts) and the
[demonstration limits](docs/research-preview.md#interpreting-the-result) and
[evidence record](docs/evidence.md) for the exact boundaries.
Run hostile code only in an appropriately isolated, explicitly authorized environment.
Do not expose a gateway publicly merely because local authentication tests pass.

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
