# Toolchain-supplied runtime notices

`rust-1.97.1-COPYRIGHT-library.html` preserves the Rust standard-library copyright
report supplied with the selected Rust 1.97.1 toolchain, from
`share/doc/rust/COPYRIGHT-library.html`. One final LF was added; the original content
is otherwise unchanged. This is an upstream notice, not Keep's legal interpretation.

Original toolchain file SHA-256:
`0a65bb747c49c7bb816cbc7188319bd6e4e8d08091c1190b8a3c0971c47968ed`

Retained file SHA-256:
`968db7452f5df771f045063a28073bf1b93b3f51d8a792e2c2af7e9eecf11205`

The original file came from the toolchain acquired for the documented development
build. Its notice bytes are not covered by the compiler/library inventory's hashes;
the hashes above identify the retained input, not independent ownership clearance.
The file covers multiple standard-library platforms/dependencies, not just code
linked into Keep. It is separate from the Cargo/npm inventory in
`THIRD_PARTY_NOTICES.txt`.

## Static target inputs

The selected compiler reports source commit
`8bab26f4f68e0e26f0bb7960be334d5b520ea452`. Its upstream
[bootstrap code](https://github.com/rust-lang/rust/blob/8bab26f4f68e0e26f0bb7960be334d5b520ea452/src/bootstrap/src/core/build_steps/compile.rs)
copies musl libc/startup objects into the self-contained target. It builds
`crtbegin`/`crtend` from LLVM compiler-rt, not GCC's similarly named objects, and
builds LLVM libunwind through the
[LLVM build steps](https://github.com/rust-lang/rust/blob/8bab26f4f68e0e26f0bb7960be334d5b520ea452/src/bootstrap/src/core/build_steps/llvm.rs).
The [pinned musl build recipe](https://github.com/rust-lang/rust/blob/8bab26f4f68e0e26f0bb7960be334d5b520ea452/src/ci/docker/scripts/musl-toolchain.sh)
specifies musl 1.2.5 with two local security patches. These are release-source
declarations, not an independent rebuild of the toolchain's distributed objects.

The following complete upstream notice files are retained byte-for-byte. No license
alternative, exception, attribution or disclaimer has been removed. The linked
sources identify the reviewed revisions; the checker contains the exact SHA-256
values and refuses changed/missing files. This adds documentation, not dependencies.

| Retained file | Upstream input |
| --- | --- |
| [musl-1.2.5-COPYRIGHT.txt](musl-1.2.5-COPYRIGHT.txt) | [musl v1.2.5 COPYRIGHT](https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT?h=v1.2.5) |
| [compiler-builtins-LICENSE.txt](compiler-builtins-LICENSE.txt) | [Rust pinned source, compiler-builtins LICENSE](https://github.com/rust-lang/rust/blob/8bab26f4f68e0e26f0bb7960be334d5b520ea452/library/compiler-builtins/LICENSE.txt) |
| [libm-LICENSE.txt](libm-LICENSE.txt) | [Rust pinned source, libm LICENSE](https://github.com/rust-lang/rust/blob/8bab26f4f68e0e26f0bb7960be334d5b520ea452/library/compiler-builtins/libm/LICENSE.txt) |
| [compiler-rt-LICENSE.txt](compiler-rt-LICENSE.txt) | [Pinned LLVM compiler-rt LICENSE](https://github.com/rust-lang/llvm-project/blob/dcc3606807c989700e0ac1cac18c31741bcd40d9/compiler-rt/LICENSE.TXT) |
| [compiler-rt-CREDITS.txt](compiler-rt-CREDITS.txt) | [Pinned LLVM compiler-rt CREDITS](https://github.com/rust-lang/llvm-project/blob/dcc3606807c989700e0ac1cac18c31741bcd40d9/compiler-rt/CREDITS.TXT) |
| [libunwind-LICENSE.txt](libunwind-LICENSE.txt) | [Pinned LLVM libunwind LICENSE](https://github.com/rust-lang/llvm-project/blob/dcc3606807c989700e0ac1cac18c31741bcd40d9/libunwind/LICENSE.TXT) |

LLVM commit `dcc3606807c989700e0ac1cac18c31741bcd40d9` is the gitlink recorded at
`src/llvm-project` in the selected Rust source commit. Upstream contributor names
and contact details in CREDITS are preserved as attribution; they are not Keep
security contacts, staff or endorsements.

This covers the identified runtime families' top-level notices, not an exhaustive
object-to-source or per-file exception audit. The upstream notices themselves point
to additional source-level attributions. Inclusion does not assert that every file
or platform described is linked into Keep, or establish complete binary redistribution
clearance. The final artifact review and off-repository rights decisions remain
separate. Changing the toolchain requires revisiting these notices.
