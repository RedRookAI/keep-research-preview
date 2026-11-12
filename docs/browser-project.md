# Submit and review a repository goal in the browser

Browser submission was introduced in source 0.0.23-preview.1. The earlier .21 combined download predates the form.

[Configure and start a local instance](local-instance.md), then sign in at its console. The form uses the repository, checker, model and execution limits saved during setup.

1. Select **Submit a repository goal** and describe a bounded change with acceptance checks.
2. Submit. Keep opens the retained project with its stage, jobs and pending decision.
3. Approve preparation when required, then review the diff and check results before approving or vetoing the exact proposal.
4. Choose **Download proposal evidence** to save the patch, pinned revision, checks and decision.

Keep the form until the project appears. If submission loses its response, resubmit the unchanged goal with the original submission key to recover the same project and job. Refresh preserves the key. A new form creates a new submission identity and can start another job.

Paused workers, missing prerequisites, failures and unresolved work remain visible. Correct setup or reconcile the original job before retrying. Opening the console leaves generation stopped. CLI and OpenClaw use the same runtime; organization routes retain their separate requirements.

## Observed browser result

On November 12, Chromium 151 completed submission, preparation approval, a workspace edit, two unchanged passing checks, same-key recovery, veto and evidence download. The test used two authored responses, automated decisions and zero paid calls.

The tested source was `6da002fdc720ac2a61273178470261b26826e716`; 93 focused checks passed with no skips. The retained console capture shows the proposal before veto:

https://raw.githubusercontent.com/RedRookAI/keep-research-preview/main/docs/images/browser-goal-console-2026-11-12.png

The fixture and runner are `acceptance/browser_project_fixture.mjs` and `acceptance/browser_project.mjs`. Running them requires an available browser driver and browser. Public HTTPS hosting is covered by the separate [guided-demo observation](guided-demo.md).

[Proposal export guide](proposal-export.md).
