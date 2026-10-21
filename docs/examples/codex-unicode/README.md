# Reproduce the genuine case's recorded patch

This is the **corrected example export**, checked October 21, 2026. It fixes a missing final newline in `proposal.patch` that made ordinary `git apply` reject the original exported file. The repair adds only that newline; `check.mjs` is unchanged. It does not run a model again.

The original October 20 execution record is `result.json`. Its patch hash identifies the original defective export and is deliberately preserved. Use `export-correction-2026-10-21.json` for current file hashes, the new reproduction result and the old-archive inventory. `independent-check.tap` is historical output, not today's rerun.

Select the supported Node 22 runtime, set `KEEP_EXAMPLE` to this directory's absolute path, then run in a new directory you own:

```sh
export KEEP_EXAMPLE=/absolute/path/to/this/example
git clone https://github.com/sindresorhus/escape-string-regexp.git keep-specimen
git -C keep-specimen switch --detach 21c557c7f14a112eebe196abd98d085f5fcfcf5e
KEEP_CASE_SOURCE="$(pwd)/keep-specimen" node "$KEEP_EXAMPLE/check.mjs"
```

The original baseline must report **one failure (Unicode hyphen), two passes**. Then apply the distributed patch directly:

```sh
git -C keep-specimen apply "$KEEP_EXAMPLE/proposal.patch"
KEEP_CASE_SOURCE="$(pwd)/keep-specimen" node "$KEEP_EXAMPLE/check.mjs"
```

Expected: **three passes, no failures**. Do not preprocess or normalize the patch. This reproduction changes the specimen checkout; it is separate from Keep's historical veto that left the original task source unchanged. Upstream source retains its MIT terms in `UPSTREAM-LICENSE`.
