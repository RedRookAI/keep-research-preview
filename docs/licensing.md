# Licensing and attribution

Keep's original code uses the [MIT license](../LICENSE). Third-party works retain
their own terms. [NOTICE](../NOTICE), [THIRD_PARTY_NOTICES.txt](../THIRD_PARTY_NOTICES.txt)
and the [native runtime notices](../native/licenses/README.md) accompany the package.
This preparation does not change any license selection.

## Review status

| Material | Completed check | Boundary |
| --- | --- | --- |
| Original Keep code | Founder ownership/disclosure confirmation recorded | Separate third-party terms still apply |
| Vendored Rust source | All 2,742 retained files across 34 package directories match registry-checksummed archives | Byte provenance, not malware analysis or an authorship guarantee |
| Three locked npm packages | Manifests and discovered notice files match integrity-checked registry archives | Not a separate comparison of every npm source file |
| Rust standard library and static runtime families | Retained toolchain copyright report and pinned-source musl, compiler-builtins/libm, compiler-rt and libunwind notices; byte-drift checks | Release-source attribution, not exhaustive object-to-source binary attestation |
| Shipped microVM asset | The asset is Keep's guest-supervisor text script | No kernel, rootfs image or model weights are included there |

No specific third-party licensing conflict was identified in these checks. They are
not a certification of legal compliance. A newly identified conflicting term or
restricted asset must be resolved for the affected material before distribution.
Report concrete concerns through the private route described in [Security](../SECURITY.md).

## What the notice tool checks

The notice bundle covers packages under native/vendor-p2 and native/vendor-transport,
plus the installed packages in package-lock.json. It includes development packages
and source that is not necessarily linked into shipped executables; it is not a
binary-linkage SBOM.

For each package it records declared identity, license, registry locator, locally
recorded archive identity and discovered license/notice/copyright texts. Nested
notices and TypeScript's third-party text are retained. Display text uses LF line
endings; digests bind the original bytes. License alternatives and additional AND
obligations are preserved rather than silently discarded.

The tool checks local notice bytes and declared identities. The separate upstream
comparisons above establish more than this local checker alone does. Neither check
establishes ownership, complete secret detection or the truth of every upstream
declaration. The naming-based notice inventory does not independently interpret
obligations embedded elsewhere in source or documentation.

Native runtime notices are retained separately, including compiler-rt's referenced
credits. Their README identifies pinned upstream origins. Byte/version checks reject
missing or changed notices; those files do not inflate the Cargo/npm package count.

## Source-builder commands

~~~sh
npm ci
node tools/release_notices.mjs --check
npm run build
~~~

Dependency installation does not compile native code. Building requires the pinned
toolchain and host build tools in the [preview guide](research-preview.md).

Ordinary npm pack checks notices and builds the installable package. That package
contains packer-built native executables, not every source-build prerequisite.
The complete source archive is provided separately. Use the accompanying
KEEP_RELEASE.md to identify the exact source/package and completed checks.

Direct git/GitHub-URL dependency installation is not a qualified route. Use the
documented source build or the reviewed binary package; binary consumers do not need
the development packages or source notice checker.

To propose a bundle update, run node tools/release_notices.mjs and review the output.
The --check mode rejects a stale bundle, missing metadata/notices, unsupported
declarations, identity mismatches, unsafe paths, symlinks and special files. It does
not install dependencies or contact a registry, model or licensing service.

## Distribution boundary

This preview is a reviewed source selection, not the private development history.
Any later addition of a VM image, model, dataset, binary or copied asset needs its
own provenance and redistribution review. Changing the selected inputs can
invalidate earlier checks. Personal and organization distributions carry the same
required attribution; this does not qualify their operational behavior.
