# A configured repository goal with solve

Development source 0.0.11-preview.1 connects `keep solve` to the existing project runtime. The downloadable 0.0.5-preview.1 archive predates this change. Use a build/install of the new source checkpoint; no replacement downloadable artifact is qualified here.

Configure the provider using the existing provider profile/environment contract. Repository work also requires KEEP_REPOSITORY, KEEP_WORKSPACE_BASE (separate from the source), KEEP_REVISION (exact commit), KEEP_REPO_REF, KEEP_BASE_BRANCH (defaults to main, must point at that commit), and KEEP_TEST_COMMAND with optional KEEP_TEST_ARGS_JSON. Run `keep doctor` first; its readiness result is configuration evidence, not a model-quality or production-host qualification. `keep onboard` captures directives; it does not configure these execution settings.

```sh
keep solve "Correct the retry limit; preserve unrelated behavior and tests"
```

Solve accepts a description and no options. It starts with approval required, including when KEEP_PROJECT_POSTURE is autonomous. The printed run and decision identify the next operation:

```sh
keep project resume <run-id> --approve=<decision-id>
```

Keep materializes the exact source revision into a workspace. The runtime records the change proposal, diff/rollback information and test results; follow its printed controls. Pending project work uses project resume/merge controls, rather than the injected legacy solver's `keep review` queue. A merge decision is bound to the exact proposal digest:

```sh
keep merge <run-id> approve --proposal=<sha256>
keep merge <run-id> veto --proposal=<sha256>
```

A decision does not grant missing merge authority. Inspect a refused or held result; do not treat exit success for a recorded decision as proof that source changes landed. The original repository remains unchanged while a proposal awaits a decision. Existing owner-token checks and organization session/roster/custody restrictions apply; remote gateway solve uses the same authenticated project endpoint.

IS001 acceptance uses an installed package and a controlled loopback model endpoint. It establishes command routing, approval, a useful test-fixture edit and review/restart behavior. It does not establish real-model success rates, production isolation, live organization onboarding or a newly qualified release archive.
