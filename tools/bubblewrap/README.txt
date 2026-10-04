Keep-specific Bubblewrap security update candidate

The old pinned identity is affected by GHSA-pxhw-h44j-8pfx. The upstream fix starts
at 0.12.0; this candidate uses upstream 0.13.0. This is a source and dependency
update, not a host-wide package upgrade. No exploit reproduction is needed.

The TypeScript launcher, native P2-D2 supervisor and qualification probe all use
/opt/keep/bubblewrap/0.13.0/bwrap and require the SHA256 in identity.json. Missing
bytes, mismatched bytes and the previous system binary must refuse admission.
There is no PATH lookup or environment-variable override for this executable.

Build only in an isolated container:

  docker build --memory=768m --memory-swap=768m \
    --cpu-period=100000 --cpu-quota=100000 \
    -t keep-bubblewrap-candidate -f tools/bubblewrap/Dockerfile .

The Dockerfile validates the upstream source checksum before compilation and
records resolved build-package versions inside /build/build-packages.txt. The
base image and upstream source are pinned, but Debian build packages are resolved
from the configured repositories. This is not a fully reproducible toolchain
claim. A build with different resolved packages may produce different bytes.
Do not change the trusted digest simply to accept a different build: inspect its
provenance and qualify that exact executable, then update all three pins together.

Extract the executable and package record from your own stopped build container
into a private staging directory. Check its SHA256 against identity.json. Retain
the source archive and license with any separately distributed binary. Bubblewrap
0.13.0 is LGPL-2.1-or-later. The npm package does not bundle this executable.

Install only inside the intended isolated qualification/deployment environment,
at the exact dedicated path. Every ancestor must be root-owned and protected
from group/other writes. The executable must be root-owned, mode 0755, with no
setuid, setgid or file capabilities. Leave /usr/bin/bwrap and other services alone.
Installation requires the operator's deployment authority; building/staging this
candidate does not authorize a privileged installation on a shared host.

Required verification before enabling the updated boundary:
  1. Typecheck and run test/bubblewrap_identity.test.ts after compilation.
  2. At the real launcher entry point, verify missing and mismatched binaries
     refuse before a task marker appears, including when environment overrides
     point to the old system binary.
  3. In a namespace-capable isolated environment, run all required_project_jail,
     required_project_jail_layout and required_project_jail_options tests. Retain
     useful-work, network, limits, descriptor-custody and setup-status controls.
  4. Rebuild the native supervisor with the pinned Rust toolchain and rerun the
     native P2-D2 confinement probe with its separately qualified systemd/cgroup
     prerequisites. Old supervisor binaries retain the old identity.
  5. Run the selected release profile, rebuild the Keep package, and qualify the
     exact installed artifact. Publish fresh checksums and an accurate evidence
     record only through the normal authorized release process.

Do not reuse the previous release's evidence as qualification for new bytes.
If prerequisites are unavailable, keep the affected required boundary unavailable
and report the missing qualification. Never fall back to an unrestricted task.

Upstream references:
https://github.com/containers/bubblewrap/security/advisories/GHSA-pxhw-h44j-8pfx
https://github.com/containers/bubblewrap/releases/tag/v0.13.0
