# Architecture

## Security boundary under test

```text
Normal World (attacker-controlled)                Secure World

client workers ---- Linux TEE driver ---- SMC ---- OP-TEE threads
      |                  |                           |
      |             RPC request queue <--- yield ---+
      |                  |
      +---- adversarial tee-supplicant workers -----+
                 | delay / reorder / cross-bind
                 | replay / fail / mutate SHM
                 v
        append-only semantic event trace
                 |
          invariant checker
                 |
       minimal violating history

        multi-run history corpus
                 |
       dynamic relation extraction
                 |
      AI-consumable element graph

FF-A actor -------- arm_ffa_user -------- SMC ---- OP-TEE SPMC / stock SPs
   | share / retrieve request / relinquish / reclaim / access probe
   +---------- generation + receiver + refcount history ---------+
```

OP-TEE documents that dynamic shared memory is registered by Normal World and
that secure-world services obtain RPC payloads from the REE. The Linux OP-TEE
driver supports asynchronous supplicant requests by adding a meta parameter
containing a request identifier. Those two mechanisms create the natural
control plane for TEEWeaver.

Primary interfaces:

- [OP-TEE core/shared-memory documentation](https://optee.readthedocs.io/en/4.0.0/architecture/core.html)
- [OP-TEE REE TA loading flow](https://optee.readthedocs.io/en/4.3.0/architecture/trusted_applications.html)
- [GlobalPlatform TEE Client API v1.0.1](https://globalplatform.org/specs-library/tee-client-api-specification/)
- Local Linux request binding: `linux/drivers/tee/optee/supp.c`
- Local supplicant RPC dispatcher: `optee_client/tee-supplicant/src/tee_supplicant.c`
- Local secure RPC suspend/resume path:
  `optee_os/core/arch/arm/kernel/thread_optee_smc.c`

## Components

### 1. History generator

Produces actor-local legal operations and interleaves them with a PCT-style
scheduler. Actors include client sessions, secure threads, supplicant workers,
reset controller, and eventually interrupt/power-management actors. Actor-local
order is preserved; only cross-actor order changes.

### 2. Adversarial REE adapter

The first real adapter is an AArch64 `LD_PRELOAD` library around
`TEE_IOC_SUPPL_RECV`, `TEE_IOC_SUPPL_SEND`, shared-memory registration, and
descriptor close. It can:

- observe request function, asynchronous request ID, response, and parameter
  metadata, plus the Linux driver's actual send/receive `ioctl` result;
- assign a generation to each reused shared-memory ID;
- delay a selected response;
- force a selected return value;
- swap two concurrent response request IDs for the same RPC function.

The same L0 library has a separately gated FF-A adapter around the public
`arm_ffa_user` ioctls. It observes `SHM_INIT`, `MSG_SEND`, `SHM_DEINIT`, and
buffer access without modifying OP-TEE or an SP. For the stock test SP protocol
it reconstructs:

- globally normalized handle generations across independent client processes;
- intended receiver and per-receiver retrieve reference count;
- accepted retrieve/relinquish/reclaim transitions;
- accepted SP read/write probes after a retrieve;
- rejected versus accepted stale-handle operations.

Its generic one-fault grammar delays a transition, repeats the exact valid
request, or substitutes one handle bit. The campaign planner derives target
action numbers and cut points only from the clean runtime trace.

The swap is intentionally performed at the documented asynchronous response
identifier. It does not corrupt secure-world code or patch the target logic.
Whether OP-TEE safely rejects or semantically tolerates a cross-bound response
is what the target-specific workload must determine.

### 3. Semantic trace

Every event is a JSON object. Required fields are `seq`, `op`, and `actor`.
Security-relevant optional fields include:

```json
{
  "seq": 17,
  "op": "rpc_reply",
  "actor": "supplicant-1",
  "request": "10",
  "claims_request": "9",
  "func": 2,
  "session": "session-b",
  "object": "41",
  "generation": 3,
  "epoch": 1,
  "fault": "swap-pair",
  "ioctl_result": 0
}
```

### 4. Oracles

The checker is stateful and independent of source-code coverage. Current
oracles are defined in `docs/INVARIANTS.md` and implemented in
`src/teeweaver/oracles.py`.

The checker separates **stimulus** from **violation**. For example, a malicious
supplicant swapping two response IDs is a stimulus. It becomes a violation only
after a Secure-World marker or end-to-end functional oracle proves that the
wrong content was accepted/consumed. A rejection such as `TEE_ERROR_SECURITY`
is a successful negative control.

### 5. Reproducer/minimizer

The event history is the canonical reproducer. Delta debugging removes events
while preserving a selected violation code. The next backend layer will bind
the minimized history to QEMU's `icount` record/replay facility so that a
specific world-switch schedule can be replayed and reverse-debugged.

### 6. Dynamic element miner

The miner consumes complete runs, incomplete bounded runs, and reset epoch
histories together. It deliberately sits before vulnerability promotion. Its
nine extractors recover relationships that a single code snapshot or a single
exit status cannot establish:

1. resource identity or allocation spanning principals;
2. action pairs whose observed order co-varies with outcome;
3. later use of state touched by a failed transition;
4. owner-to-receiver handoffs;
5. raw identity reuse over distinct generations;
6. cross-endpoint serialization/contended transaction domains;
7. state observed across a reset epoch;
8. issued calls with no matching return marker; and
9. different semantic histories hidden behind the same visible result.

`elements.json` is designed as an AI input, not a scanner finding format. Every
record includes supporting event references, why runtime evidence was needed,
known alternative explanations, explicit falsifiers, next experiments, and
root-cause search hints. `not_a_vulnerability` is always true at this layer.

## Instrumentation levels

| Level | Target modifications | Purpose | Evidence strength |
|---|---|---|---|
| L0 | None in Secure World; malicious supplicant interposer only | Real attacker-visible RPC/SHM behavior | Strongest discovery/reproduction tier |
| L1 | Linux tracepoints/kprobes or driver logging | Recover request identities and timings | Strong diagnosis; repeat at L0 before reporting |
| L2 | OP-TEE trace build or test TA emits semantic markers | Observe verify/use, owner, and session context | Oracle development and root cause, not final exploit proof alone |
| L3 | QEMU plugin/watchpoint/record-replay | Memory generation, world switches, deterministic replay | Strong temporal evidence; validate on stock binary afterward |

The framework must always record which level produced a result.

## Implementation phases

1. **MVP (complete):** event model, seven invariant classes, semantic-state
   cardinality, PCT scheduling primitive, delta minimization, RPC/SHM interposer.
2. **QEMU integration (implemented for RPC and FF-A workloads):** the automated runner boots a
   pinned four-core QEMU-v8 image, instruments the first supplicant, runs clean
   and adversarial paired-client workloads, records both worlds, checks
   artifacts, and emits a machine-readable summary. Workload manifests are
   data-driven. For FF-A it also stages the upstream `arm_ffa_user` module,
   rejects silently skipped tests, and records stock SP lifecycle transitions;
   deterministic `icount` record/replay remains.
3. **Memory identity:** track registered address/length, mmap/close, page content
   digests, and controlled ABA reuse.
4. **Reset/storage (partial):** a minimal-init backend provides a single
   host-backed REE-FS image across cold boots, emits storage acknowledge/
   observe events, and validates both a clean restart and an older-image replay
   ground truth. Generic in-flight cut points and production RPMB anchors remain.
5. **FF-A ownership (implemented for Normal World to stock test SP):** handle
   generation, receiver references, rejected early reclaim, balanced reclaim,
   and stale retrieve are checked. Stable multi-actor scheduling and opaque
   SP-to-SP internal memory transactions remain partial.
6. **Coverage guidance:** corpus queue keyed by semantic state plus optional
   secure-world edge coverage.
7. **Evaluation:** seeded mutants, known historical fixes, equal-budget
   baselines, new findings, and unmodified-target confirmation.
