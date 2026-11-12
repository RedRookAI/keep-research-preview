# Toolchain-supplied runtime notices

`rust-1.97.1-COPYRIGHT-library.html` contains the selected Rust 1.97.1 toolchain's standard-library copyright report from `share/doc/rust/COPYRIGHT-library.html`. One final LF was added; the remaining upstream content is unchanged.

Original toolchain file SHA256:
`0a65bb747c49c7bb816cbc7188319bd6e4e8d08091c1190b8a3c0971c47968ed`

Retained file SHA256:
`968db7452f5df771f045063a28073bf1b93b3f51d8a792e2c2af7e9eecf11205`

These hashes identify the notice separately from the compiler/library inventory. It covers several platforms and dependencies, including material beyond Keep's linked code. Cargo/npm notices are in `THIRD_PARTY_NOTICES.txt`.

## Static target inputs

The selected compiler reports source commit `8bab26f4f68e0e26f0bb7960be334d5b520ea452`. Its bootstrap recipe copies musl libc/startup objects into the self-contained target, builds `crtbegin`/`crtend` from LLVM compiler-rt and builds LLVM libunwind:

https://github.com/rust-lang/rust/blob/8bab26f4f68e0e26f0bb7960be334d5b520ea452/src/bootstrap/src/core/build_steps/compile.rs

https://github.com/rust-lang/rust/blob/8bab26f4f68e0e26f0bb7960be334d5b520ea452/src/bootstrap/src/core/build_steps/llvm.rs

The pinned musl recipe specifies **1.2.5** with two local security patches. These are upstream build declarations; the distributed toolchain objects were not independently rebuilt here.

https://github.com/rust-lang/rust/blob/8bab26f4f68e0e26f0bb7960be334d5b520ea452/src/ci/docker/scripts/musl-toolchain.sh

The following upstream notice files are retained byte-for-byte, including all alternatives, exceptions, attributions and disclaimers. The checker verifies their SHA256 values and refuses missing or changed files.

[musl-1.2.5-COPYRIGHT.txt](musl-1.2.5-COPYRIGHT.txt), from musl v1.2.5:

https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT?h=v1.2.5

[compiler-builtins-LICENSE.txt](compiler-builtins-LICENSE.txt), from the pinned Rust source:

https://github.com/rust-lang/rust/blob/8bab26f4f68e0e26f0bb7960be334d5b520ea452/library/compiler-builtins/LICENSE.txt

[libm-LICENSE.txt](libm-LICENSE.txt), from the same source:

https://github.com/rust-lang/rust/blob/8bab26f4f68e0e26f0bb7960be334d5b520ea452/library/compiler-builtins/libm/LICENSE.txt

[compiler-rt-LICENSE.txt](compiler-rt-LICENSE.txt):

https://github.com/rust-lang/llvm-project/blob/dcc3606807c989700e0ac1cac18c31741bcd40d9/compiler-rt/LICENSE.TXT

[compiler-rt-CREDITS.txt](compiler-rt-CREDITS.txt):

https://github.com/rust-lang/llvm-project/blob/dcc3606807c989700e0ac1cac18c31741bcd40d9/compiler-rt/CREDITS.TXT

[libunwind-LICENSE.txt](libunwind-LICENSE.txt):

https://github.com/rust-lang/llvm-project/blob/dcc3606807c989700e0ac1cac18c31741bcd40d9/libunwind/LICENSE.TXT

LLVM commit `dcc3606807c989700e0ac1cac18c31741bcd40d9` is the `src/llvm-project` gitlink in that Rust revision. CREDITS preserves upstream contributor names and contact details as attribution.

This inventory covers the identified runtime families' top-level notices. Complete object-to-source mapping, per-file exceptions and final redistribution clearance remain outside that review. Upstream notices identify further source-level attributions. Revisit the inventory when the toolchain changes.
