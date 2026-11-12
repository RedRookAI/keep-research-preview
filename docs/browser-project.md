# Submit and review a repository goal in the browser

Source 0.0.23-preview.1 adds goal submission to Keep's existing project console. The current .21 download predates this browser submission form; use the qualified release instructions for that artifact.

Configure and start an owned instance using the local-instance guide, then sign in at its console. The owner selects the repository, checker, model and execution limits during setup. The form uses those saved settings.

1. Select **Submit a repository goal** and describe a bounded code change with its acceptance checks.
2. Submit the form. Keep opens the retained project, including its current stage, worker state, jobs and any pending decision.
3. If a step needs approval, inspect it and choose whether to proceed. Review the actual proposed diff and executable check results before approving or vetoing the exact proposal.
4. Choose **Download proposal evidence** to retain the patch, pinned revision, checks and decision record.

If the response to submission is lost, keep the original form and unchanged goal. Resubmitting with its original submission key recovers the same project and job. Refreshing the form preserves that key and does not start work. Starting a new form creates a new submission identity.

Paused workers, missing prerequisites, failed jobs and unresolved work remain visible. Correct the reported setup or reconcile the original job before retrying. Opening the console never starts generation. CLI and OpenClaw remain supported clients of the same runtime; organization routes retain their existing qualification holds.

## Observed browser result

On November 12, Chromium 151 completed the actual form, step approval, a real workspace edit, two unchanged passing checks, same-key recovery without another submission job, exact-proposal veto and browser evidence download. The sample used two explicitly scripted responses and zero paid calls. Browser decisions were driven by the test; this result does not measure live model quality or qualify a hosted deployment.

The inspected source was 6da002fdc720ac2a61273178470261b26826e716. Its runtime source was integrated unchanged; the source checkpoint separately updates version metadata and public CI coverage. Ninety-three focused checks passed with no skips. The actual console capture below shows the checked proposal before veto:

https://raw.githubusercontent.com/RedRookAI/keep-research-preview/main/docs/images/browser-goal-console-2026-11-12.png

The reusable account-free fixture and browser runner are in `acceptance/browser_project_fixture.mjs` and `acceptance/browser_project.mjs`. They use the real composed application and authored sample responses. The runner requires an already available browser driver and browser; those tools are not runtime dependencies of Keep.

Instance setup:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/local-instance.md

Proposal evidence:

https://github.com/RedRookAI/keep-research-preview/blob/main/docs/proposal-export.md
