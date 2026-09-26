# Paper and evaluation plan

## Working title

**TEEWeaver: History-Guided Adversarial REE Testing for Cross-World Security
Invariants in OP-TEE**

## Claims we may test

- **H1:** semantic cross-world state coverage retains security-relevant tests
  that edge coverage considers equivalent.
- **H2:** an adversarial RPC/SHM/reset environment reaches OP-TEE failures that
  TA-command and syscall mutation alone do not reach.
- **H3:** PCT-style low-depth schedule exploration reaches violating histories
  more efficiently than uniform random delays.
- **H4:** history recording plus QEMU deterministic replay and delta debugging
  materially improves reproducibility and root-cause time.
- **H5:** a corpus-level dynamic element graph gives an AI agent more useful
  experiment targets than source-only findings or crash/exit-status triage,
  measured by controlled-hypothesis yield and duplicate-adjusted valid bugs.

These remain hypotheses until experiments are run.

## Anti-overfitting protocol

The framework is not designed around the trigger sequence of a published
advisory. Its core must be frozen before known-case evaluation:

1. Derive invariants from the OP-TEE, Linux TEE, FF-A, and GlobalPlatform
   contracts and from the stated malicious-REE threat model.
2. Define protocol-level operations such as delay, reorder, replay, reuse,
   cancellation, reset, and byte mutation without naming a vulnerable function
   or advisory.
3. Freeze the event schema, mutation grammar, scheduler, state key, and oracles
   under a versioned artifact.
4. Run the frozen artifact first against current supported targets. New
   candidates are minimized without consulting the known-case registry.
5. Only after minimization, consult public advisories for duplicate triage.
6. Separately run the same frozen artifact against quarantined vulnerable and
   fixed revisions. No benchmark-specific rule, yield point, workload branch,
   or oracle may be added between the two runs.

For example, a workload that explicitly races a named operation against a
known vulnerable implementation is not a framework result. A generic ownership
and lifetime campaign that independently reaches that history, while also
exercising other resources and producing distinct candidates, is useful
evidence of generality.

The strongest paper result is therefore simultaneous breadth:

- known vulnerabilities emerge without advisory-specific tuning;
- clean/fixed targets remain negative;
- the same frozen machinery finds previously unknown, semantically distinct
  violations; and
- ablation shows that semantic history coverage or schedule guidance was
  necessary to retain those executions.

## Experimental targets

- Upstream OP-TEE `main` at pinned commits.
- At least two recent releases or maintenance branches.
- QEMU-v8 SMC ABI plus the implemented Normal-World `arm_ffa_user` FF-A
  lifecycle adapter; opaque SP-to-SP transitions remain a separate backend.
- Supported configurations involving dynamic SHM, REE-FS, RPMB emulation,
  concurrent supplicant workers, cancellation, and suspend/resume.
- A physical board only for candidates whose behavior depends on cache,
  translation, RPMB, interrupt, or reset hardware not faithfully modeled by
  QEMU.

## Baselines

1. Same legal workloads with no fault injection.
2. Uniform random delay/reorder without semantic coverage.
3. Edge coverage with the same mutation budget.
4. OP-TEE AFL syscall fuzzer for syscall-facing seeded bugs.
5. State-sequence mutation without generation/epoch oracles.
6. Where artifacts permit, published TEE state-aware approaches on their
   supported targets; otherwise explicitly report non-comparability.

## Ground truth

Create small, reviewable seeded faults representing:

- response ID ignored or response payload cross-bound;
- SHM generation not advanced after reuse;
- verified buffer retained by reference and changed before use;
- failed operation publishes a cache/global object;
- acknowledged storage metadata written in a rollback-prone order;
- cancellation resumes or cleans up the wrong session.

Seeded bugs measure sensitivity; they are not counted as new vulnerabilities.

## Metrics

- unique semantic states and secure-world edges;
- time-to-first violation and executions-to-violation;
- schedule bug depth;
- reproducibility over 30 independent replays;
- minimized history length and number of actors;
- false-positive rate after manual/specification validation;
- new valid bugs, upstream acknowledgements, CVEs, and severity;
- runtime, snapshot, trace, and instrumentation overhead.
- element precision: fraction of mined elements that survive their stated
  falsifier and produce a controlled, causal experiment;
- downstream utility: time and experiments required for an AI agent to turn an
  element into either a rejected hypothesis or a promoted finding.
- semantic discovery throughput: normalized features and controlled contrasts
  per target-hour and per CPU-hour;
- corpus efficiency: retained histories divided by observed histories, with
  all discarded decisions reproducible from the streaming index;
- AI query yield: fraction of queued relationships that produce a falsifiable
  one-change experiment rather than an unbounded source-search task.
- observation yield: normalized high-signal transitions per target-hour,
  reported by source and parser rule together with ignored-line coverage;
- false-order rate: synthetic cross-stream collisions that must remain absent
  when Normal- and Secure-World logs have no shared clock.

## Ablations

- remove generation from state key;
- remove request identity;
- remove reset epoch;
- crash-only oracle versus semantic oracles;
- random scheduler versus PCT;
- edge-only versus semantic-only versus combined feedback;
- Normal-World-only versus native-secure-log-augmented semantic feedback;
- independent order domains versus an intentionally unsafe concatenated-log
  total order;
- with and without deterministic replay.

## Reproducibility record

Every published run must include:

- target commit hashes and complete config;
- QEMU/Linux/OP-TEE/client commits;
- seed, scheduler depth, actor programs, and fault rules;
- instrumentation level;
- raw JSONL history and minimized history;
- vulnerable and fixed/negative-control logs;
- scripts that rebuild and replay the experiment.

## Publication discipline

- Describe the literature gap as “not found in reviewed work” until the review
  is exhaustive.
- Separate seeded, rediscovered, and genuinely new bugs.
- Do not infer exploitability from a crash or oracle violation alone.
- Coordinate disclosure before publishing a new security finding.
