# TEEWeaver

TEEWeaver is a dynamic semantic-element mining and adversarial state-machine
testing framework for OP-TEE. Its
primary target is not a parser or an individual Trusted Application. It tests
security properties that span the untrusted Rich Execution Environment (REE),
the Linux TEE driver, `tee-supplicant`, OP-TEE RPC suspension/resumption,
shared-memory lifetimes, and reset epochs.

The central research question is:

> Can an attacker-controlled REE make OP-TEE accept a result in a different
> security context, generation, lifetime, or epoch from the one in which the
> result was requested or authenticated?

This repository currently contains a dependency-free executable research core,
a deterministic trace format, semantic security oracles, schedule exploration,
trace minimization, and an AArch64 `LD_PRELOAD` interposer for the real
OP-TEE `tee-supplicant` and `arm_ffa_user` ABIs. It is a working research
prototype, not a claim that a new OP-TEE vulnerability has been found.

Version 0.2 adds a corpus-level element miner. It does not emit vulnerability
reports. It converts multiple histories into evidence-backed, AI-consumable
hypotheses about hidden resource scope, order sensitivity, failure residue,
ownership transfer, ABA reuse, serialization, reset persistence,
nontermination, and state aliasing. Each element carries caveats, falsifiers,
and the next experiments needed to promote or reject it.

## Validated status

The current prototype has been exercised end to end on the pinned upstream
QEMU-v8 environment with four secure-world cores:

- clean control: `xtest 1001` completed 624 subtests with zero failures;
  15,270 events produced no attack stimuli and no invariant violations;
- adversarial control: two concurrent signed-TA loads produced 13,830 events;
  four LOAD_TA responses were cross-bound and all four `TEE_IOC_SUPPL_SEND`
  calls returned zero, proving Linux accepted the response IDs;
- Secure World rejected the mismatched results with `TEEC_ERROR_SECURITY` and
  `TEEC_ERROR_SHORT_BUFFER`; the checker therefore reported four stimuli and
  zero accepted violations.
- a manifest-driven `xtest 1013` concurrency campaign ran two clean controls
  and eight protocol-derived faults. Five runs were stimulus-only, two caused
  expected defensive workload failures, one swap attempt did not pair, and no
  accepted invariant violation occurred;
- the panic-concurrency campaign (`xtest 1040`) ran two clean controls and
  eight protocol-derived faults. Four executions produced attack stimuli and
  four reached new semantic states, with zero accepted violations;
- the stock QEMU FF-A test SP completed the full Normal-World-to-SP memory
  lifecycle (25 subtests): two retrieves, access, rejected early reclaim,
  balanced relinquish/reclaim, and rejected stale retrieve. The merged trace
  passed the receiver/refcount/generation oracles;
- a twelve-run advisory-blind FF-A campaign produced eight stimulus-only runs
  and four expected workload failures. No stale retrieve, live-borrower
  reclaim, invalid relinquish, or post-reclaim access was accepted;
- the corpus-level miner has been validated against complete, failed, reset,
  and bounded/incomplete histories. Candidate-specific evidence is withheld
  from the public research preview pending root-cause analysis;
- a minimal-init, host-backed REE-FS backend preserved one acknowledged object
  across a real cold QEMU restart and observed the identical value with zero
  violations;
- replaying an older, previously valid REE-FS image produced the expected
  `PERSISTENCE_ROLLBACK` oracle violation. This is labelled ground truth—not a
  vulnerability—because the tested QEMU build has `CFG_INSECURE=y` and no RPMB
  integrity anchor;
- client ioctl tracing is quarantined: with tracing disabled, all 14
  cancellation subtests pass; with it enabled, one cancellation result changes.
  The latter is an observer effect and is excluded from discovery results.

This is a negative control, not a vulnerability. It demonstrates that the
framework can create and distinguish a real cross-world semantic fault without
mistaking expected rejection for a finding.

## Why this is different

Most TEE fuzzers mutate TA commands, system calls, or message fields and use
code/state coverage or crashes as feedback. TEEWeaver instead mutates legal
cross-world histories and checks external security invariants. Interesting
inputs include:

- two valid RPCs whose responses are delayed or cross-bound;
- a valid shared-memory identifier that is released and reused at a new
  generation;
- bytes that are valid when authenticated but different when consumed;
- a failed/cancelled operation whose effects survive and are consumed later;
- a persistent operation interrupted across a reset boundary.

The framework deliberately treats a crash as only one possible symptom. A
successful call with the wrong identity, bytes, owner, lifetime, or epoch is a
more important result.

## Quick start

Run the self-contained oracle demonstrations and tests:

```sh
cd teeweaver
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m teeweaver.cli check scenarios/clean_rpc.jsonl
PYTHONPATH=src python3 -m teeweaver.cli check scenarios/cross_bound_rpc.jsonl
PYTHONPATH=src python3 -m teeweaver.cli minimize scenarios/cross_bound_rpc.jsonl /tmp/minimized.jsonl
```

Build the real AArch64 supplicant interposer against the existing QEMU-v8
Buildroot toolchain:

```sh
make -C instrumentation/supplicant_preload \
  OPTEE_ROOT=/path/to/optee-qemu-v8
make -C instrumentation/ffa_probe \
  OPTEE_ROOT=/path/to/optee-qemu-v8
```

The produced `libteeweaver.so` can be copied into the QEMU guest and loaded
only for `tee-supplicant`. See
[`instrumentation/supplicant_preload/README.md`](instrumentation/supplicant_preload/README.md).

Run an isolated QEMU experiment without changing the existing OP-TEE trees or
rootfs overlay:

```sh
PYTHONPATH=src python3 tools/run_qemu_experiment.py --workload baseline
PYTHONPATH=src python3 tools/run_qemu_experiment.py --workload load-ta-swap
PYTHONPATH=src python3 tools/run_qemu_experiment.py --workload cancellation
PYTHONPATH=src python3 tools/run_qemu_experiment.py --workload ta-concurrency
PYTHONPATH=src python3 tools/run_qemu_experiment.py --workload panic-concurrency
PYTHONPATH=src python3 tools/run_qemu_experiment.py --workload storage-concurrency
PYTHONPATH=src python3 tools/run_qemu_experiment.py --workload ffa-memory-lifecycle

# Validate reset freshness mechanics, then the documented insecure replay control.
PYTHONPATH=src python3 tools/run_reset_experiment.py --mode clean
PYTHONPATH=src python3 tools/run_reset_experiment.py --mode ree-replay

# Derive a protocol-only plan from three clean executions and run it.
PYTHONPATH=src python3 tools/run_campaign.py \
  --workload storage-concurrency --baseline-runs 3 --seed 260926 --budget 12

# Derive FF-A action/lifetime faults only from a clean observed history.
PYTHONPATH=src python3 tools/run_campaign.py \
  --workload ffa-memory-lifecycle --baseline-runs 3 --seed 260926 --budget 12

# Mine all nine element classes from the bundled synthetic public corpus.
python3 tools/mine_elements.py
```

Each run creates a self-contained result directory containing Normal/Secure
World logs, supplicant trace, xtest output, exit status, pinned commits, stimuli,
and end-to-end violations. The LOAD_TA swap workload is a defensive negative
control: on the tested build it produces cross-binding stimuli but zero accepted
violations.

Workloads are data-driven in `scenarios/workloads.json`; adding an official
`xtest` sequence does not require changing the runner. Diagnostic workloads
without a stable passing baseline are marked `campaign_eligible: false` and
cannot be selected by the automated campaign driver.

Before known-case evaluation, freeze the generator, scheduler, event schema,
oracles, instrumentation, tests, and research protocol:

```sh
python3 tools/freeze_artifact.py
python3 tools/freeze_artifact.py --verify artifacts/freeze-v0.2.0-alpha.json
```

Validate the adopted result set and hash every evidence file separately from
the code freeze:

```sh
python3 tools/build_evidence_manifest.py
python3 tools/build_evidence_manifest.py --verify artifacts/evidence-v0.2.0-alpha.json
```

An oracle result is not automatically disclosure-ready. Apply the mechanical
reportability gate with an evidence record:

```sh
python3 tools/promote_candidate.py RUN/summary.json evidence.json
```

## Repository map

- `src/teeweaver/`: trace, state model, security oracles, PCT scheduler,
  delta minimizer, and the nine-class dynamic element miner.
- `instrumentation/supplicant_preload/`: no-secure-world-modification RPC/SHM
  and FF-A observation plus controlled Normal-World faults.
- `instrumentation/ffa_probe/`: independent Normal-World actor for existing
  upstream FF-A test SPs; it makes no Secure-World modification.
- `scenarios/`: small positive and negative histories used to test the oracles,
  plus the manifest for the bundled synthetic element-mining corpus.
- `examples/public-corpus/`: non-product synthetic histories exercising all
  nine element classes without publishing coordinated-research candidates.
- `docs/RESEARCH.md`: literature map and the precise research gap.
- `docs/ARCHITECTURE.md`: target architecture, event flow, and trust levels.
- `docs/INVARIANTS.md`: machine-checkable security properties.
- `docs/PAPER_PLAN.md`: hypotheses, evaluation design, baselines, and
  non-overclaiming rules.
- `docs/THREAT_MODEL.md`: attacker capabilities and bounty-relevant gates.
- `docs/DUPLICATE_FIREWALL.md`: semantic duplicate fingerprint and promotion
  gate.
- `docs/COVERAGE_MATRIX.md`: implemented, partial, quarantined, and planned
  critical boundaries.
- `docs/OBSERVER_EFFECTS.md`: invalidated instrumentation paths and A/B proof.
- `docs/RESULTS_V0_1.md`: accepted controls, campaign outcomes, and excluded
  debugging runs for the frozen prototype.
- `docs/ELEMENT_MINING.md`: element schema, mining rules, confidence limits,
  and AI consumption contract.
- `docs/RESULTS_V0_2.md`: sanitized public-preview validation scope.
- `evaluation/known_cases.json`: quarantined known OP-TEE cases used only after
  a framework version is frozen; generation and scheduling code never imports
  this file.

## Evidence discipline

Instrumentation-assisted failures are discovery evidence, not automatically a
reportable vulnerability. Clean baselines containing any oracle violation stop
the campaign. A candidate is promoted only after it reproduces on an
unmodified target with a realistic Normal-World attacker and demonstrates a
concrete Secure-World confidentiality or integrity violation.

## License

TEEWeaver is released under the BSD 3-Clause License. See [LICENSE](LICENSE).
