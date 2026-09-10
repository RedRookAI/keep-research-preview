# Research at Keep

Keep is being developed to give AI agents responsibility for projects that continue
across sessions: work that accumulates knowledge, changes direction, and requires
decisions about what to do next. Our goal is to make that work more capable and less
demanding to supervise.

We study the software around the model as part of that problem. What the agent
remembers, which procedures it reuses, how a change is accepted, and what happens
after an interrupted action all influence the result. Keep brings these mechanisms
into a self-hosted runtime so they can be developed and evaluated together.

The intended users range from an individual working with one model connection to
an organization coordinating several agents. Software development is our
best-developed setting: changes can be executed, tested, compared, accepted, and
reversed. The research also covers the shared resources, private information, and
external services involved in longer assignments.

## A working platform for the research

The [control and oversight research brief](security-experiments.md) proposes
studies of long-running agent teams, learning from unreliable experience, and
recovery after compromised information spreads. Their shared question is how to
give agents more useful responsibility while keeping people in control.

Keep's native coding loop reads a permitted repository snapshot, requests model
proposals, applies edits in a work area, and runs repository checks. Acceptance and
merge policy determine which changes reach the original project. Persistent memory
supplies versioned sources; skill and adaptation mechanisms provide ways to propose
and evaluate changes in later behavior.

The runtime also includes delegated permissions, shared-resource accounting,
recovery records, deployment checks, and a hash-linked audit history. These are
useful experimental controls. They give studies a starting point for varying a
memory policy or skill-selection method while holding tasks, permissions, and
outcome checks comparable; each study must qualify the connections it uses.

Development results provide three starting points:

- **Repository work.** Recorded installed workflows have produced a model-proposed
  repair that passed a separate repository test while preserving the original
  source. Other workflows exercised approval, refusal, merge, restart, and
  revert. The fixture workflow reconstructs runtime state; separate recovery cases
  exercise fresh processes.
- **Memory used during coding.** In one authored task family, a model retrieved
  retained information, distinguished an earlier setting from its corrected value,
  and produced a repair that passed separately defined repository checks. The task
  ran in personal and simulated organizational configurations.
- **Recovery after a lost response.** The introductory experiment records an effect
  in a durable local service and then loses the acknowledgment. The corrected
  runtime retains the resource obligation across restart, blocks excess work, and
  permits further work when capacity remains. The experiment also checks concurrent
  and restarted reuse of dispatch permits.

These results were administered in the development environment. Their source
revisions, configurations, and scope are recorded in the [evidence record](evidence.md).
The [preview guide](research-preview.md) provides the runnable entry point.

## Memory that remains useful as a project changes

A long-running project can contain several valid versions of an instruction. A
later task may require the old value, the current value, or the reason for the
change. Access to the underlying information may change as well.

Keep retains sources with revision and eligibility information and supplies selected
passages to its native coding workflow. The current research asks how those choices
affect completed work: which history should remain available, how conflicting
information should be presented, and when a change should invalidate a pending plan.

The next comparisons would use task sequences with explicit corrections, conflicting
sources, and withdrawn access. Competitors would include retained conversation
history and retrieval systems given the same versions and validity information.
We would measure later task correctness, exposure to ineligible material,
unnecessary interruptions, and total retrieval and inference cost. Supplied passages
and observable actions would be recorded separately from claims about a model's
internal reliance on a source.

A useful outcome would be a memory design that helps an agent work correctly as a
repository evolves, along with task sequences and results that other developers
can reproduce. The temporal-memory demonstration supplies an initial combined
workflow; broader transfer is the question for the proposed study.

Implementation: [task context](../src/memory/task_context.ts).
Configuration: [semantic memory and private retention](semantic-memory.md).

## Learning which changes to keep

An agent can revise a prompt, prefer a different strategy, or retain a procedure
after completing a task. Establishing that the change helped requires a reliable
connection between the change, the tasks on which it was used, and the resulting
performance.

Keep's outcome-adaptation machinery records baseline and candidate assignments,
exposure, and project-owned outcomes. It preserves that state across restart and
provides rollback. This gives us a starting point for studying promotion decisions
over a sequence of tasks.

The proposed studies would compare these decisions with fixed behavior and
well-configured retrieval or reflection methods. Evaluation would include held-out
task families, regressions on earlier tasks, and the cost of acquiring and evaluating
experience. We also want to understand what happens when information supporting a
useful adaptation is corrected or withdrawn.

The aim is to identify changes that keep earning their place as the workload
evolves. A resulting method could help maintainers improve an agent over time while
keeping the cost of evaluation and repair visible.

Implementation: [outcome adaptation](../src/learning/outcome_adaptation.ts).

## Skills with demonstrated task value

Reusable procedures can save an agent from solving the same problem repeatedly.
They can also carry assumptions, permissions, and failure modes from the setting
in which they were created.

Keep has mechanisms for extracting action patterns from successful traces,
receiving candidate skills, comparing performance with and without a skill, and
managing admission, retirement, and rollback. Foreign-skill intake currently
produces a proposed replacement specification. Completing the path from that
specification to a tested executable replacement is a research and engineering
opportunity.

A central question is whether receiver-side evaluation can preserve useful
functionality with less unnecessary access and fewer harmful effects. Comparisons
would include direct generation from an authorized task specification, existing
skills under restrictive execution controls, and conventional scanning and task
tests. The same task requirements and permission limits would apply to every method.

The measurements are concrete: successful task completion, permissions requested
and used, harmful effects, false rejection, and evaluation cost. Held-out tasks
would test whether a procedure remains useful beyond the examples used to develop it.

Implementation: [distillation](../src/loop/skill_distiller.ts),
[comparative evaluation](../src/loop/skill_evaluator.ts), and
[skill registry](../src/registry/skill_registry.ts).

## More reliable code changes

An agent may generate several plausible repairs. Tests can help choose between
them, but generating and checking extra candidates consumes resources and can leave
a person with more material to review.

Keep includes repository localization, bounded candidate generation, separate
workspaces, and verification-guided selection. Optional generated tests can
investigate behavioral differences between candidates. The acceptance workflow
then applies the configured merge policy.

We want to determine when these mechanisms increase the number of correct accepted
changes at an acceptable cost. Studies would hold tasks, model access, repository
checks, and permissions constant while varying candidate generation and selection.
Outcomes would include regressions, incorrectly accepted changes, human intervention,
and total cost per correct completion.

This work could give developers practical guidance on where additional inference
and verification are worth using. It also provides a setting for testing whether
improved memory and skills translate into better software work.

Implementation: [native proposal loop](../src/solve/edit_planner.ts) and
[governed merge](../src/solve/governed_local_merge.ts).

## Coordination through interruption and changing authority

Several agents may share a budget, modify related state, or depend on one another's
changes. An operation can also take effect before its response is lost. Recovery
has to account for work that is already underway while responding to changes in
permission or supporting information.

Keep's fleet mechanisms track shared capacity, selected rollback dependencies,
supplied provenance, and declared common-cause limits. Durable admission and dispatch
records preserve obligations across the tested restart boundaries. The introductory
experiment gives us an executable starting point for extending that work.

The proposed comparisons would test concurrent work, uncertain outcomes, and
authority changes against competent transactional coordination and serialized
execution. All methods would receive the same service observations and relevant
state. We would examine when recovery can observe and settle an earlier operation,
when another action needs fresh authority, and how long uncertainty blocks useful
work. An idempotent retry may still initiate a first effect; it is not automatically
a read-only observation.

The intended result is a tested recovery contract and evidence about which
coordination rules preserve useful concurrency. Important measures include actual
effects, duplicate execution, resource-limit violations, unresolved obligations,
and completion of work outside the affected resource and dependency boundaries.

Implementation: [fleet lifecycle](../src/fleet/fleet_lifecycle.ts) and
[delegated authority](../src/identity/delegation_registry.ts).

## Delegation with practical human control

The purpose of delegation is to reduce the work a person must supervise. Its value
depends on which decisions remain with the operator and how the system handles
private information.

Keep includes scoped grants, permission attenuation, expiration, revocation, and
separate acceptance powers. Privacy mechanisms control eligible context and
configured provider disclosure. Operator-facing workflows handle questions and
decisions about the proposed work.

Research in this area would compare task-scoped delegation and targeted intervention
with approval-heavy and conventional permissioned workflows. It would measure
correct completion, prohibited actions, disclosed information, and the time a person
spends interpreting or resolving requests. Corrections and revoked permissions
would be introduced at specified points in the task.

The goal is to identify controls that let people delegate more substantial work
without a corresponding increase in supervision. Privacy studies would also measure
the effect of information transformations on the quality of completed tasks.

Implementation: [delegation](../src/identity/delegation_registry.ts) and
[provider disclosure controls](../src/privacy/egress_interceptor.ts).

## Evidence an operator can use

An operator needs to know which restrictions are active in a particular deployment
and what evidence exists when an action goes wrong. Available kernel features,
configuration declarations, and observations of actual behavior answer different
parts of that question.

Keep's enforcement profiles distinguish enforced, detected-only, unavailable, and
unknown controls. Its capability graph relates components, entry points, credentials,
and effects to observations with artifact identities and freshness information.
The audit spine records hash-linked events, pre-effect intent, and witnessed
checkpoints on its participating paths.

These mechanisms support two related investigations. Deployment studies would test
whether the evidence helps identify absent or bypassable protections.
Execution-history studies would examine which conclusions a verifier can reach about
permission, attempted work, observed effects, and recovery. Privacy constraints make
the second question more demanding: the evaluator may have access to only part of
the underlying information.

Comparisons would use ordinary configuration checks and evidence-processing methods
with the same observations. Measurements would include unsupported positive
decisions, missed harmful effects, useful work refused, verification overhead, and
the information disclosed to the evaluator. Some cases should remain unresolved
when the available observations are insufficient.

Possible outputs include a portable qualification package, reference evidence
bundles, and a verifier that other agent developers can use. Their value would be
demonstrated through the decisions they improve and the work they save.

Implementation: [enforcement profiles](../src/platform/enforcement_profile.ts),
[capability graph](../src/graph/capability_graph_v2.ts), and
[witness export](../src/witness/witness_export.ts).

## Research across models and deployments

Keep's native runtime and configurable model interfaces provide a way to compare
methods across models and operating arrangements. Each study would identify its
supported routes and record the model, configuration, resource use, and relevant
execution boundaries.

Open-model inference could provide additional control over checkpoints and serving
behavior. Weight adaptation is a further research extension: Keep contains
orchestration interfaces, while a working training backend and its end-to-end
evaluation remain to be developed and qualified. One longer-term comparison would
ask whether accumulated memory, learned skills, or parameter adaptation lets a
smaller model complete a task stream at lower total cost than a larger fixed model.

These studies would be useful to operators choosing between hosted and local
resources, including individuals running a single endpoint and organizations
coordinating several workloads.

## Comparison with existing work

The agenda intersects established work on agent learning, coding, runtime policy,
and evidence. [Reflexion (v4, October 2023)](https://arxiv.org/abs/2303.11366v4)
studies learning through recorded feedback.
[AgentCL (v2, June 2026)](https://arxiv.org/abs/2606.02461v2) examines controlled task
streams and transfer, while [MemSkill (v2, May 2026)](https://arxiv.org/abs/2602.02474v2) studies
learned memory-management procedures.
[Forgetting Without Restarting (v1, September 2026)](https://arxiv.org/abs/2609.04875v1) investigates
selective repair of execution state after information is revoked.

For coding, [CodeMonkeys](https://scalingintelligence.stanford.edu/blogs/codemonkeys/)
provides a relevant comparison for multiple candidates and test-guided selection.
[CaMeL (v2, June 2025)](https://arxiv.org/abs/2503.18813v2) examines control and information-flow
enforcement. [Stateful Governance for Concurrent Agentic Systems (v2, August 2026)](https://arxiv.org/abs/2608.02764v2)
addresses authorization over changing shared state. The informational
[RATS architecture, RFC 9334](https://www.rfc-editor.org/info/rfc9334/), provides
established terminology for evidence producers, verification, and freshness.

These starting references were checked on September 9, 2026. Each study would
identify the particular version, method, and implementation being tested, its
assumptions, and the setting in which Keep's approach might improve performance
or operating cost.

## How the studies would be evaluated

A study would state its task distribution, success conditions, threat assumptions
where relevant, and resource budget before the main comparison. Competing methods
would receive matched information and permissions. Learning experiments would
separate development tasks from held-out evaluation and isolate accumulated state
between methods and repetitions. Public fixtures are exposed development material,
not unseen evaluation tasks.

Coding outcomes would use separately defined repository checks. Effect studies
would inspect the controlled service or filesystem. Model participation, scripted
behavior, test administration, and outside replication would be recorded explicitly.
Evaluation costs would include learning, checking, recovery, and operator effort
as applicable.

Reports would retain failures and unresolved cases and identify the settings in
which simpler methods are sufficient. The resulting evidence should let another
developer decide which mechanisms are worth adopting.

## Next stage

The proposed next stage is a set of targeted studies built on this runtime:
representative tasks, credible comparison implementations, repeated model
evaluations, and externally administered runs. Individual projects can produce
useful software and findings while contributing to the larger goal of agents
that take responsibility for more demanding work.

Keep is developed by Red Rook AI. Start with the [project introduction](../README.md),
[preview guide](research-preview.md), and [evidence record](evidence.md).
