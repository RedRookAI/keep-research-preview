# Keep release record

## This candidate

**Keep 0.0.1 — keep-preview-2026-09-09.2. Public research preview.**

This is the current record for the two archives below. It is a companion document,
not part of either prepared archive. The source revision identifies the development input;
the selected source archive, not private Git history, is the distribution subject.

| Item | Exact identity |
| --- | --- |
| Source revision | `b4c0c77a89e1b2b3d1613ab11bb3251eb84b2b62` |
| Source selection digest | `1bac8fe17e2f18d3fe46e981c034ec2372a0ae3ac04b82ac20c20d961bc6408d` |
| Source archive | `keep-source-preview.tar.gz` — 16,275,635 bytes; 3,949 members |
| Source archive SHA256 | `81dab7fafc30061fa85495a2d683f9600f8eef0506eee23e8382dfd6e0d7ed20` |
| Installable package | `keep-0.0.1.tgz` — 6,251,659 bytes; 2,086 members |
| Package SHA256 | `5bd03fd022d85a0a1f129c3396edc88c77016851feec4b0dc4addeb0c0768d78` |

For the checksum-gated installation block in docs/research-preview.md, set:

~~~sh
export KEEP_RELEASE_SHA256='5bd03fd022d85a0a1f129c3396edc88c77016851feec4b0dc4addeb0c0768d78'
~~~

Do not derive the expected value from the downloaded archive. A checksum compares
bytes; it does not independently authenticate this record's publisher.

## Checks performed on this revision

- TypeScript compilation and 16 focused documentation/attribution tests passed.
  Local document links and heading targets were checked. The checksum-command
  test covers matching, mismatched, malformed, unset and missing-archive inputs;
  failures stop before installation.
- All eight public pages were rendered using the existing Markdown renderer with
  table support; generated HTML and structure were inspected. All 12 shell blocks
  passed syntax checks. This was local HTML inspection, not a GitHub browser test.
- Selected source built with empty npm cache and ordinary scripts-enabled npm ci
  and npm pack. Native outputs were freshly compiled.
- A separate empty-cache consumer installed the exact package normally.
- The network-disabled installed demonstration passed 16 accounting and eight
  single-entry cases, with zero model calls.
- Direct reads matched all 24 local sink outcomes to the report: 20 sink files
  and four zero-effect cases without a file.
- The source archive matches the complete selection; the package contains the
  new evidence page, eight runtime-notice paths and guest-supervisor text asset.

The broader experimental suite and historical model workflows were not rerun.
Their original identities, failures and scope are retained in docs/evidence.md.

## Environment and carried-forward evidence

Linux x64; Node.js 22.23.2, npm 10.9.8, Rust 1.97.1 targeting x86_64-unknown-linux-musl,
GCC 13.3 and binutils 2.42. Build and consumer ran sequentially in isolated arrangements
limited to one CPU, 2 GiB RAM, no swap and 128 tasks, on the maintainer's existing host.
The build took 41.121 seconds; the separate install/demo check took 14.467 seconds.

The previously acquired pinned Rust installation was reused read-only at a different
path. Private source paths, prior native outputs and prior npm caches were not supplied.
The compiler was not reacquired. Compared with the preceding candidate, changes are
public documentation, its package inclusion and link tests. Native and dependency-lock
inputs are unchanged. Completed vendor provenance and runtime attribution checks
were carried forward for those exact inputs, not rerun or relabeled as new.

## Known limits

This is a builder-administered synthetic result, not outside replication, production
identity qualification, remote-effect finality or general coding/recovery assurance.
The sink does not model every possible provider behavior.

Historical source 63cbf80 had 4,497 passes and 11 failures in the broader portable
profile; its release/security phase did not run. Five repository-flow cases still
failed after the workspace prerequisite was supplied. Those and the missing
solver-result finding remain relevant limits on broader workflow claims, not
environment-only dismissals. See docs/evidence.md for the classification and history.

The original-code ownership confirmation and vendor byte comparison are complete.
These checks do not claim blanket legal compliance or malware absence.

## Publication record

Lisa explicitly authorized this publication as owner of Red Rook AI LLC.

- Repository: https://github.com/RedRookAI/keep-research-preview
- Release: https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-preview-2026-09-09.2
- Public snapshot/tag commit: `4b42436867a0eb16b23065203ef38a3639830ed7`
- Originating development revision: `b4c0c77a89e1b2b3d1613ab11bb3251eb84b2b62`

The tagged root commit contains exactly the 3,949 reviewed source files, with no
private Git history. Main-branch publication-status documentation is a separate
successor; the tagged source and two prepared archives are unchanged. Documents
inside the prepared archives retain pre-publication wording; use this record and
the main-branch security policy for current publication status.

GitHub private vulnerability reporting is enabled and its enabled state was read
back through GitHub's API. Maintainer notification delivery has not been verified.
Lisa should select Watch → Custom → Security alerts on this repository. If she
wants email delivery, she must also enable Email under her personal notification
settings, Subscriptions → Watching. No email address, response deadline, bounty
or paid service is introduced.

The existing private repositories remain private. This publication contains no
private development/backup history or internal funding material and does not
include npm-registry publication.
