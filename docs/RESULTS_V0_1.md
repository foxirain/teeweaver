# Results ledger for v0.1 research freeze

Date: 2026-09-26.

This ledger separates valid controls and campaigns from infrastructure/model
iterations. A workload failure, hang, stimulus, or new semantic state is not a
security finding unless a security invariant is demonstrably accepted by the
target.

`scenarios/evidence-v0.1.json` is the machine-readable adoption list.
`tools/build_evidence_manifest.py` refuses any result whose summary no longer
matches the expected outcome, then hashes every file into
`artifacts/evidence-v0.1.json`.

Adopted-evidence aggregate SHA-256:
`621b2bb49affe12f1bd94b31234729f2c7810337d9f9654ec368694ccc7d1dde`.

## Target

- `optee_os`: `5858c37a66cbffccf7b047d0f9a52dee0ebbf06c`
- `optee_client`: `ba3dce76046dcaf6cc496ee8a93191029f8090ae`
- `qemu`: `7c949c53e936aa3a658d84ab53bae5cadaa5d59c`
- `linux`: `cf6e3218c25183cbc45551e85d0dd531f00fcc3d`
- `build`: `581cb28f79504e31773634f66f01e3b8fa6e7136`

The result summaries also record the working-tree status and hashes of the
actual QEMU, kernel, rootfs, BL1, OP-TEE configuration, and interposer used.

## Valid controls

| Result | Target behavior | Oracle result | Interpretation |
|---|---|---|---|
| `results/validation-baseline-v2` | `xtest 1001`, 624 subtests, status 0, 15,270 events | 0 stimuli, 0 violations | clean RPC baseline |
| `results/validation-baseline-post-ffa-v1` | post-FF-A-adapter `xtest 1001`, status 0, 15,314 events | 0 stimuli, 0 violations | RPC non-regression control |
| `results/validation-load-ta-swap-v10` | concurrent signed TA loads, four cross-bound replies accepted by the Linux SEND ioctl; workloads reject them | 4 stimuli, 0 violations | adversarial negative control |
| `results/validation-memref-v10` | real mapped byte mutation during TA loading; both official tests remain defensive | 1 stimulus, 0 violations | byte-mutation negative control |
| `results/validation-cancellation-ab-control-v1` | client tracing off; all 14 cancellation subtests pass | 0 violations | clean cancellation control |
| `results/validation-ffa-lifecycle-v2` | stock `ffa_spmc 1002`, 25 subtests pass | 0 stimuli, 0 violations | clean FF-A lifecycle control |
| `results/reset-clean-control-v9` | acknowledged REE-FS value survives a cold QEMU restart unchanged | 0 violations | clean reset control |
| `results/reset-ree-replay-ground-truth-v2` | older valid host REE-FS image is replayed after a newer value was acknowledged | `PERSISTENCE_ROLLBACK` | expected ground truth on `CFG_INSECURE=y`, not a vulnerability |

## Completed discovery campaigns

| Campaign | Clean baselines | Fault runs | Classification | Accepted violations |
|---|---:|---:|---|---:|
| `campaign-20260926-ta-concurrency-v3` (`xtest 1013`) | 2 | 8 | 5 stimulus-only, 2 behavioral symptoms, 1 semantic novelty | 0 |
| `campaign-20260926-panic-concurrency-v1` (`xtest 1040`) | 2 | 8 | 4 stimulus-only, 4 semantic novelty | 0 |
| `campaign-20260926-ffa-lifecycle-v1` (`ffa_spmc 1002`) | 2 | 12 | 8 stimulus-only, 4 behavioral symptoms | 0 |

The FF-A campaign plan was derived from observed action numbers,
handle-bearing relations, reclaim operations, and cardinalities. It exercised
delay, exact-request duplication, and one-bit handle substitution. No rule
contains a source location, advisory identifier, or known trigger sequence.

## Non-finding but useful multi-actor observation

`ffa-memory-parallel` uses two independent Normal-World processes and two stock
test SPs. Both actors can complete repeated lifecycles when calls are
interleaved, but other clean schedules yield transient `EBUSY` responses or an
unreturned direct-message ioctl. There is currently no stable clean baseline,
no proven contract violation, and no confidentiality/integrity impact.
Consequently the manifest marks this workload `campaign_eligible: false`.

This observation is a scheduler/backend engineering target, not a bounty or
CVE candidate.

## Excluded iterations

- `validation-ffa-lifecycle-v1`: the FF-A test was silently skipped because the
  user module was not staged. The runner now requires at least one FF-A event.
- `validation-ffa-parallel-v1` and `v2`: both processes targeted singleton test
  state or lacked retry handling; not clean controls.
- `validation-ffa-parallel-v3`: apparent generation violations were caused by
  per-process observation counters. The merge layer now normalizes generations
  from global share order and has a regression test.
- `validation-ffa-parallel-v4`: interrupted multi-actor liveness experiment;
  not a complete result.
- `validation-ffa-rollback-control-v1`: stock outer `ffa_spmc 1007` returned
  `0xff` rather than `SPMC_TEST_OK` on this build. With no internal SP-to-SP
  transaction trace or clean passing control, this is only a diagnostic
  failure and the workload is campaign-ineligible.
- `campaign-20260926-ta-concurrency-v1` and `v2`: model/instrumentation
  iterations before process-role identity was corrected.
- reset runs before `reset-clean-control-v9` and
  `reset-ree-replay-ground-truth-v2`: runner/prompt/storage-image debugging.
- cancellation tracing-on results: excluded by OE-001 because instrumentation
  changed the official test outcome.

## Security conclusion at freeze

No new reportable High/Critical OP-TEE vulnerability has been established by
this artifact. The contribution at this point is a tested framework and a set
of negative/ground-truth controls that resist several common false-positive
paths: skipped tests, instrumentation timing changes, process-local identity
collisions, expected defensive failures, and insecure-reference rollback.
