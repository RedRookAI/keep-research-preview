# Reproduce the recorded Codex patch

The October 21, 2026 export correction adds the final newline missing from `proposal.patch`; `check.mjs` is unchanged. The original file caused `git apply` to reject it.

`result.json` records the October 20 generation, including the old patch hash. `export-correction-2026-10-21.json` supplies current hashes and the reproduction result. `independent-check.tap` retains the original test output.

Use the supported Node 22 runtime and a new specimen directory:

```sh
export KEEP_EXAMPLE=/absolute/path/to/this/example
git clone https://github.com/sindresorhus/escape-string-regexp.git keep-specimen
git -C keep-specimen switch --detach 21c557c7f14a112eebe196abd98d085f5fcfcf5e
KEEP_CASE_SOURCE="$(pwd)/keep-specimen" node "$KEEP_EXAMPLE/check.mjs"
```

The baseline should report **one failure (Unicode hyphen), two passes**. Apply the patch directly:

```sh
git -C keep-specimen apply "$KEEP_EXAMPLE/proposal.patch"
KEEP_CASE_SOURCE="$(pwd)/keep-specimen" node "$KEEP_EXAMPLE/check.mjs"
```

Expected result: **three passes, no failures**. Leave the patch bytes unchanged. These commands modify the specimen checkout; Keep's historical veto preserved its original task source. Upstream MIT terms are retained in `UPSTREAM-LICENSE`.
