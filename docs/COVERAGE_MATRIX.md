# Critical-boundary coverage matrix

This matrix is the boundary of the current claim. “Implemented” means a real
upstream QEMU execution emits events and the oracle is exercised. “Partial”
means either the stimulus or the observation exists, but the complete
stock-target security oracle does not. “Planned” is not counted as coverage.

| Boundary / state machine | Attacker operation | Observation / oracle | Status | Evidence |
|---|---|---|---|---|
| REE RPC request/response identity | delay, force return, bounded cross-bind | request identity, response claim, Linux acceptance, Secure-World workload result | Implemented | LOAD_TA negative control and RPC campaign |
| RPC response bytes in registered SHM | single-byte mutation at observed memref | exact before/after byte, driver acceptance, verification failure | Implemented | `validation-memref-v10` |
| Supplicant SHM identity/generation | allocate, register, map, close/reuse observation | stale-generation and use-after-release history oracles | Partial | Real registration/mapping events; no stock target stale-use sink yet |
| TA loading / authenticated-byte continuity | mutate loader result; compare verification/use digest | rejection and workload result | Partial | Mutation is real; Secure-World verify/consume digest taps are absent |
| Concurrent TA/session lifetime | official multi-thread workloads plus RPC scheduling faults | crash/status/semantic history; owner/lifetime oracle where events exist | Partial | `xtest 1013`; no Secure-World object-lifetime tap |
| Panic / teardown interaction | official panic-concurrency workload plus RPC faults | workload status, RPC history, native panic/release, session destroy, TA-context destroy, and FF-A resurrection events | Partial | `xtest 1040`; internal events are normalized, but no accepted security-property violation or stock-target causal reproducer yet |
| Secure storage / RPMB emulation | error, delay, byte mutation during concurrent storage | workload result, RPC/SHM history | Partial | `xtest 6016` campaign; reset/commit oracle not wired |
| Client cancellation | issue/cancel/complete ordering | cancellation atomicity | Quarantined | Current client interposer changes timing; OFF control passes, ON fails |
| Reset / persistence epoch | cold restart and replay of an older valid REE-FS image | acknowledged-version freshness after reset | Implemented for QEMU ground truth | clean restart retains the value; insecure no-RPMB replay triggers `PERSISTENCE_ROLLBACK` |
| FF-A Normal World → SP memory ownership | delay, duplicate, handle substitution across share/retrieve/relinquish/reclaim | globally normalized handle generation, intended receiver, retrieve refcount, accepted SP access | Implemented | stock `ffa_spmc 1002`; 12-run advisory-blind campaign, zero accepted violations |
| FF-A multi-actor scheduling | independent Normal-World actors targeting two stock SPs | merged handle generations and per-SP history | Partial / quarantined from campaigns | both actors can complete, but some concurrent direct-message histories return EBUSY or do not complete; no stable clean baseline yet |
| FF-A SP→SP internal memory ownership | stock rollback/multiple-receiver actions | outer direct-message result plus native SPMC map/retrieve/refcount/rejection records | Partial | `ffa_spmc 1003`–`1007`; internal events are visible, but an external content oracle and full share/lend provenance remain |
| CPU migration / interrupt / suspend | PCT scheduling plus native Secure-World notification sleep/wake logs | per-core active context and quiescence | Partial | Thread/core scheduling is normalized; interrupt and power transitions still require secure tracepoints or emulator hooks |
| Platform MMU/cache/DMA | translation/cache/DMA perturbation | confidentiality/integrity of protected mappings | Planned | QEMU evidence is insufficient for hardware-specific claims |

## Honest whole-project interpretation

TEEWeaver targets the *critical cross-world state machines* of OP-TEE, not every
source line. The current executable backend is strong at the malicious-REE
RPC boundary and provides reusable model/oracle machinery for the other rows.
It does not yet justify a claim of full OP-TEE coverage. Production-anchored
RPMB/reset campaigns, stable multi-actor FF-A scheduling, opaque SP-to-SP
transactions, and hardware-coherence backends are separate research
milestones, not hidden assumptions.

The v0.3 discovery engine expands how all implemented and partial rows are
compared: session/request/storage identities now enter one semantic resource
graph, treatment histories are ranked against clean-control coverage, and the
campaign runner maintains a streaming novelty index. This improves discovery
throughput; it does not upgrade a partial boundary to implemented unless the
underlying observation and target-specific oracle in the table are present.

## Promotion rule

A target failure remains a symptom until it has: a recorded accepted invariant
violation, stock-target reproduction, a supported configuration, a Normal-World
attacker path, concrete Secure-World security impact, a negative control,
observer-effect control, a minimized reproducer, and duplicate triage. The
machine-readable gate is implemented by `tools/promote_candidate.py`.
