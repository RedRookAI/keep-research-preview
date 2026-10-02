# Control and oversight of capable agents

Proposed research directions · September 10, 2026

## How can we empower agents while keeping people in control?

An agent that can work for days, learn new procedures, and coordinate with other
agents could take on much more useful work. It also creates a harder oversight
problem: a person cannot inspect every action, a mistake can become a reusable
lesson, and several individually reasonable steps can combine into a harmful
outcome.

Keep is being developed as a setting for investigating that problem. The aim is to
let agents take on more responsibility while preserving people's ability to set
limits, judge the results, and intervene effectively. Security matters here as a
condition for greater capability, not just a filter on individual responses.

The three directions below focus on oversight across agent teams, learning from
unreliable experience, and recovery after compromised information spreads. They
are proposed studies, not completed results. Existing research provides important
solutions and strong comparisons; the protocols must establish where a new method
adds value. These directions sit within Keep's wider
[research program](research.md), rather than defining every future use of the
platform.

## 1. Keeping oversight effective across long-running agent teams

### The problem

When several agents divide a project, no single message or action necessarily
reveals what the group is doing. A misleading result can pass between agents,
a reviewer can share the worker's mistake, or an adversarial agent can spread a
harmful plan across otherwise ordinary steps. Giving every step to a human defeats
much of the purpose of delegation.

The research question is whether oversight can detect and interrupt harmful
activity across a whole project while preserving useful autonomy under a limited
review budget. This includes ordinary shared mistakes as well as deliberately
adversarial behavior.

For example, agents might legitimately prepare a software release. The evaluator
would introduce a controlled attempt to weaken its tests or misrepresent what was
checked. The study would ask whether oversight catches the resulting problem,
including when the work and misleading evidence are distributed across agents.

### What we would investigate

We propose studying oversight that combines observations of actual effects,
cross-task history, and selective requests for human review. The central hypothesis
is that this combination can improve the amount of correctly completed work at a
given level of harmful outcomes and review effort.

Comparisons would include transcript-based monitoring, structured multi-reviewer
systems, and conventional permission and approval controls. Tests would include
reviewers from the same and different model families. Giving all methods the same
underlying observations would help distinguish better interpretation from simply
giving one method more information.

Adversarial agents would be allowed to adapt to the oversight procedure during
development. Separate evaluation campaigns would test transfer to new tasks and
attack strategies. Legitimate work must genuinely require the permissions being
tested: a system that refuses everything would not count as successful oversight.

We would measure actual harmful effects, correct completed work, missed incidents,
unnecessary interventions, detection delay, and model and human review cost.
Experiments that simulate a perfect human reviewer would be reported separately
from studies involving real people.

### What existing work already establishes

[Adaptive Attacks on Trusted Monitors](https://proceedings.iclr.cc/paper_files/paper/2026/file/54b153ad8a138f4c186f21a8b7341d5e-Paper-Conference.pdf)
shows why monitors must be tested against attackers that adapt to them.
[TraceGuard](https://arxiv.org/html/2604.03968v1) studies structured monitoring,
while [Colosseum](https://arxiv.org/html/2602.15198v1) examines collusion in
multi-agent settings. Google's
[AI Control Roadmap](https://storage.googleapis.com/deepmind-media/DeepMind.com/Blog/securing-the-future-of-ai-agents/gdm-ai-control-roadmap.pdf)
also identifies risks distributed across many agent instances.

Our proposed focus is persistent, cooperating agents under realistic limits on
review, including the reliability of the evidence on which oversight depends.
Adding another reviewing model is not itself the proposed advance. An advance
would be a method that withstands stronger adaptive tests while allowing more
legitimate work for the same oversight resources.

### What Keep contributes and what remains

Keep provides scoped delegation, separate acceptance powers, execution records,
and mechanisms for recording effects and recovery. These give us places to
implement and compare oversight decisions. Its existing local demonstration checks
effects against a controlled service; it does not establish trustworthy observation
of arbitrary agent deployments.

The study still needs a multi-agent evaluation environment, defined attacker
access, observations that tested agents cannot rewrite, and model-backed trials.
Intended outputs include reproducible task campaigns, an oversight runner, and
result bundles. Other agent-framework developers could use them to test whether
their reviewers detect distributed failures; adapters would be needed to run those
systems without adopting Keep.

## 2. Learning from experience without learning the wrong lessons

### The problem

An agent can remember an apparently successful solution and reuse it later.
But the original test may have missed a defect, the feedback may have been wrong,
or a procedure may work only in its original setting. Repetition can turn a small
evaluation mistake into a persistent habit.

The question is how an agent should decide which lessons deserve to influence
future work when reliable feedback is incomplete, delayed, or expensive. The goal
is genuine improvement on new work, not a growing library of procedures that
merely passed their own examples.

For example, a coding agent might retain a shortcut that passes an incomplete test
suite. Later tasks could reveal the error. A useful learning system would need to
reassess the lesson and related work without discarding every genuinely useful
procedure it acquired.

### What we would investigate

We propose studying how to allocate additional checks before and after promoting
a learned procedure: when to seek stronger evidence, when to hold a candidate,
and when later outcomes should trigger repair or withdrawal. Permission limits
would remain binding; a better average score would not authorize prohibited work.

Comparisons would include no accumulated learning, well-configured retrieval,
fixed skill libraries, and relevant methods that already improve memory selection
or feedback quality. All methods would face the same tasks, information, access
limits, and accounting of learning and verification costs.

Task sequences would include changing requirements, misleading apparent successes,
and feedback that becomes available only later. Evaluation would use unfamiliar
tasks and separately controlled outcome checks that are not available as answers
to the learning method.

We would measure improvement on new tasks, regressions on earlier work, reuse of
harmful procedures, useful lessons rejected, and the total cost of acquiring,
checking, and correcting experience. Comparing complete learning policies with
their simpler components would show whether added machinery earns its cost.

### What existing work already establishes

[AgentCL](https://arxiv.org/html/2606.02461v2) examines learning and transfer across
controlled task streams. [SkillLearnBench](https://arxiv.org/html/2604.20087v1)
evaluates skill learning through task outcomes. Work on
[memory reward inflation and LUCID](https://arxiv.org/html/2608.00017v1) already
examines unreliable self-scoring and external checks.
[MemSkill](https://arxiv.org/html/2602.02474v2) learns memory-management procedures.

The proposed advance must go beyond retaining successful traces or asking another
model to grade them. We would look for a reliable way to decide which evidence is
worth obtaining and how it should change future behavior under a fixed resource
budget. The exact decision method remains to be designed and compared with these
approaches.

### What Keep contributes and what remains

Keep includes [skill comparison](../src/loop/skill_evaluator.ts),
[registry lifecycle controls](../src/registry/skill_registry.ts), and mechanisms
for recording candidate assignments, exposure, and outcomes. The maintenance
preview ties relevant approval and lifecycle decisions to the checked content.
These are foundations for conducting a study, not evidence that Keep has already
demonstrated continual learning gains.

The study needs a learning policy, representative task streams, comparison
implementations, and repeated model evaluations. Foreign-skill intake currently
produces a replacement specification; producing a tested executable replacement
requires additional work.

Intended outputs include task streams, an experiment runner, and results connecting
each retained lesson to later outcomes and costs. Developers could use these to
evaluate their own memory or skill-learning policies. A separately usable runner
and its integration interfaces remain to be built.

## 3. Recovering control after compromised information has spread

### The problem

An agent may discover that information was malicious, incorrect, or no longer
authorized only after it has shaped a plan, generated a skill, or influenced
another agent. Some actions may already have affected a repository or external
service. Deleting the original memory cannot undo all of those consequences.

The research question is how to identify work that needs reconsideration, prevent
further unauthorized effects, and preserve work that remains valid when the
available history is incomplete. This is a question about the combined behavior
of learning, coordination, and the outside world.

For example, a poisoned project note might influence a generated procedure that
another agent uses. After the note is withdrawn, the system must decide what to
stop, what to check, what can be corrected, and what cannot yet be resolved.

### What we would investigate

We propose studying a recovery procedure that connects source changes, derived
artifacts, current authority, and observations of effects. The hypothesis is that
explicitly representing these relationships and unresolved questions can preserve
more legitimate work than broad invalidation, without allowing additional
unauthorized effects.

Comparisons would include version-aware retrieval, selective replay where its
assumptions apply, and full restart combined with proper external-state
reconciliation. Established transactional coordination and compensating actions
would be included where appropriate. Restarting an agent while ignoring its
previous external actions would be an inadequate comparison.

Tests would change information or authority at different stages of a multi-agent
task. Controlled services would reveal actual effects independently of agents'
claims. Each method would receive the same observations; selected cases would
withhold information to test whether the system correctly leaves an outcome
unresolved.

Measurements would include unauthorized effects after a change, duplicated work,
retained useful work, unnecessary interruptions, recovery cost, and accuracy about
what remains unknown. Some past actions cannot be undone. Detecting that limit and
escalating it accurately is part of the required behavior.

### What existing work already establishes

[Forgetting Without Restarting](https://arxiv.org/html/2609.04875v1) already studies
selective repair of reconstructible execution state, with explicit boundaries
around committed external effects.
[MemSecBench](https://arxiv.org/html/2607.27080v1) evaluates memory attacks and
downstream consequences.
[Stateful Governance for Concurrent Agentic Systems](https://arxiv.org/html/2608.02764v2)
addresses authorization over changing shared state.

The proposed focus is the combined case involving derived skills, cooperating
agents, partial observations, and effects that may already have happened. This
overlaps substantial existing work. Before a main study, we must identify a
specific failure that strong existing methods do not adequately address and a
testable improvement. Connecting components alone would not establish that advance.

### What Keep contributes and what remains

Keep's [source-linked task context](../src/memory/task_context.ts), authority
checks, and durable accounting provide starting mechanisms. Its lost-response
demonstration is a useful engineering check of a bounded recovery path. It is not
a claim to have invented reliable retries or solved this larger research problem.

The proposed combined recovery procedure, service adapters, and model-backed
evaluation still need development. Intended outputs include controlled scenarios,
effect checks, a reference recovery implementation, and comparative results.
Memory-system and agent-runtime developers could use them to investigate recovery
across their own components after suitable integration work.

## What would make these studies useful?

Each study would specify its hypothesis, comparison implementations, task
distribution, attacker powers where relevant, outcome checks, and resource budget
before the main evaluation. A promising result must improve useful completed work,
control, or oversight cost against strong alternatives—not merely pass tests written
for Keep. If existing methods solve the chosen problem adequately, we would revise
or drop that study.

Development tasks and published examples would be kept distinct from held-out
evaluation. Accumulated state would be separated between methods and repetitions.
Reports would distinguish scripted tests, model participation, human review, and
outside administration, and retain failures and settings where simpler methods
work well.

Planned public outputs include cleared tasks, runners, configurations, permitted
model outputs, resulting artifacts, outcome checks, and results with resource use.
Publication details remain subject to applicable data and model terms and
responsible disclosure. Reusable outputs should help other developers evaluate
their systems, rather than require them to accept Keep's own verdict.

Keep supplies an experimental foundation for this work. Its
[existing evidence](evidence.md) records what has actually been demonstrated; the
[research overview](research.md) covers the broader platform. Each study requires
qualification of the execution, isolation, observation, and spending boundaries it
uses. Experiments would use authorized, isolated resources, not production
credentials or uncontrolled live targets. See the [security policy](../SECURITY.md).
