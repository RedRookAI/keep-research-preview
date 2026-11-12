# Try a checked code change

A small webhook handler counts repeated deliveries twice. Keep prepares a fix in a separate workspace, runs four checks and waits for your decision.

Open the public demo directly. No sign-in is needed:

https://keep-demo.redrook.ai/console

1. Choose **Start demo**, then **Prepare the fix**.
2. Review the three repository checks and developer-authored **Goal check**.
3. Open **Inspect the code change** to see the diff.
4. Approve or veto the exact proposal, then choose **Download evidence**.

The sample uses two authored responses and needs no AI account or paid calls. Hosted approval applies the checked change to the synthetic source repository. Appliance approval retains the reviewed workspace and leaves its source unchanged. Veto preserves the proposal and evidence.

The public demo shares one disposable task. Refreshing or opening a new form returns to it, including its decision and export. If it has already been completed, inspect the retained result or run the downloadable appliance for your own copy.

## Observed browser result

On source `8f4f4da5d55781e4b8f5bb7417957fabb4079165`, version `0.0.30-preview.1`, a fresh certificate-checked Chromium 151 session completed preparation, four checks, approval and evidence download. The rendered diff, exported proposal and actual source commit matched. Both retained jobs completed with no unresolved work.

Version 0.0.30 rejects unreviewed files before staging and checks every candidate commit against the retained proposal. The current submission snapshot records the hosted observation and tested source:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/qualification/submission-snapshot-2026-11-12.json

Earlier desktop approval, phone veto and access-boundary observations remain in the [historical .25 browser receipt](qualification/guided-reviewer-2026-11-12.json). The image below shows that earlier version of the same task.

![Hosted guided start](images/guided-reviewer-start-2026-11-12.png)
