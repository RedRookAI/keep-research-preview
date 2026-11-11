# Export a retained proposal

Development source **0.0.20-preview.1** can export one retained repository proposal for review. Use the original run ID and patch SHA-256 shown by `keep project status` or the console. Export requires an authenticated human with `audit.export` permission. Restricted submission clients cannot export.

```sh
keep project export RUN_ID --proposal=PATCH_SHA256 > proposal.json
keep proposal show proposal.json
keep proposal verify proposal.json
keep proposal patch proposal.json > proposal.patch
```

The project console also offers **Download proposal evidence** beside the recorded proposal. The download uses the signed-in console session and returns an attachment with caching disabled.

The JSON bundle contains the exact diff, pinned source revision, patch digest, recorded check results, pseudonymous requester/exporter references, recorded decisions and last-recorded workspace/source delivery outcomes. Stable SHA-256 references let reviewers distinguish identities without receiving raw account names. Historical missing identities remain unknown. Decision rows retain their event, requested decision, proposal digest and recorded result status; an approval request can have a refused result. Generation approval, proposal veto, workspace merge and source landing remain separate observations.

Export reads the authenticated retained checkpoint and current event records. It makes no generation request, executes no check, changes no repository and stages no export event. A wrong proposal digest refuses. The portable projection omits prompts, task memory, raw logs and free-form diagnostics. It refuses known credentials, common credential forms, private host paths and unsafe or credential file paths. Unsupported quoted or whitespace-bearing Git paths refuse. Exact patches are never redacted because their digest binds review decisions. Inspect the patch and check names before sharing any source content.

## Check the recorded source

Use a clean checkout whose HEAD is the recorded base revision:

```sh
keep proposal verify proposal.json --repository=/absolute/path/to/clean-checkout
```

Verification checks bundle integrity, exact HEAD, clean state and `git apply --check --index`. It refuses a changed revision or dirty checkout. It disables optional index writes, hooks and filesystem monitors, and refuses configured clean filters before inspecting working-tree state. It does not apply the patch or land a change. Keep's existing exact-proposal approval and delivery controls govern source delivery.

The bundle is an **unsigned retained-evidence report**. Its digest checks content integrity; a recipient still needs to establish who supplied it and assess the recorded evidence. Delivery fields describe the last saved outcome rather than a fresh check of a remote repository.
