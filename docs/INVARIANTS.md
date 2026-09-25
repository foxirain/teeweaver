# Security invariants

These are discovery oracles, not declarations that every violation is a
High-severity vulnerability. Severity depends on reachability and concrete
Secure-World impact.

## I1. RPC identity binding

A malicious REE is allowed to send a response under any request ID. That is an
attack stimulus, not yet a vulnerability. A violation occurs only if Secure
World accepts or consumes content from a different request/context.

```text
issue(r, context=c) ; reply(delivered_to=r, content_from=r') ; accept(r)
    => r = r'
```

Stimulus codes: `RPC_ORPHAN_REPLY_STIMULUS`, `RPC_CROSS_BIND_STIMULUS`,
`RPC_CONTEXT_MISMATCH_STIMULUS`, `RPC_REPLY_REJECTED_STIMULUS`.

An `rpc_reply` is considered delivered only when the underlying Linux
`TEE_IOC_SUPPL_SEND` returns a non-negative result. A rejected ioctl remains a
stimulus and does not consume the pending request in the model.

Violation codes: `RPC_ID_REUSE`, `RPC_ACCEPT_WITHOUT_REPLY`,
`RPC_CROSS_BIND_ACCEPTED`, `RPC_WRONG_CONTEXT_ACCEPTED`.

## I2. Shared-memory generational lifetime

An SHM identifier is not an object identity by itself. Object identity is the
pair `(id, generation)`. A secure-world use must occur while that exact
generation is live.

```text
register(id,g) ; release(id,g) ; register(id,g+1)
    forbids use(id,g)
```

Violation codes: `SHM_DOUBLE_REGISTER`, `SHM_GENERATION_REGRESSION`,
`SHM_INVALID_RELEASE`, `SHM_STALE_USE`.

## I3. Owner isolation

Unless explicitly shared by the protocol, a resource created for one session,
TA, VM, or secure partition must not be consumed under another owner.

Violation code: `SHM_OWNER_MISMATCH`.

## I4. Authentication-to-use byte identity

The bytes consumed as executable code, metadata, a key, or an authenticated
object must equal the bytes covered by the successful verification for the
same object generation.

```text
verify(object,g,digest=x) ; consume(object,g,digest=y) => x = y
```

Violation codes: `USE_WITHOUT_VERIFICATION`, `VERIFY_USE_DRIFT`.

## I5. Failure and cancellation atomicity

Once an operation is reported failed or cancelled, it must not later publish a
security-relevant side effect unless the specification explicitly defines a
partial commit.

Violation code: `FAILED_OPERATION_SIDE_EFFECT`.

## I6. Reset freshness

If a persistent update is acknowledged as committed, a later reset must not
expose an older authenticated value unless rollback is explicitly permitted.

Violation code: `PERSISTENCE_ROLLBACK`.

## I7. Quiescent reset

Pending volatile request identities and live SHM generations do not survive a
platform reset in the model. A future implementation will distinguish warm
reset, suspend/resume, secure reset, and REE-only restart.

## I8. FF-A memory ownership and lifetime

An FF-A handle is identified by `(handle, generation)`. A successful retrieve
adds a receiver reference. A successful relinquish removes exactly one matching
reference. Reclaim is valid only while the generation is live and no receiver
reference remains; a successful SP access requires a live matching retrieve.

```text
share(h,g,r) ; retrieve(h,g,r) ; reclaim(h,g)
    is forbidden until relinquish(h,g,r)

reclaim(h,g) ; retrieve(h,g,r) or access(h,g,r)
    is forbidden
```

Violation codes: `FFA_LIVE_HANDLE_REUSE`, `FFA_GENERATION_REGRESSION`,
`FFA_STALE_RETRIEVE_ACCEPTED`, `FFA_WRONG_RECEIVER_RETRIEVE_ACCEPTED`,
`FFA_INVALID_RELINQUISH_ACCEPTED`, `FFA_INVALID_RECLAIM_ACCEPTED`,
`FFA_RECLAIM_WITH_LIVE_RECEIVER`, `FFA_ACCESS_AFTER_RECLAIM`, and
`FFA_ACCESS_WITHOUT_RETRIEVE`.

An injected delay, duplicate, or handle substitution is only
`FFA_ADVERSARIAL_TRANSITION_STIMULUS`; a rejected request or failed workload is
not an invariant violation.

## Required evidence for a reportable finding

1. A valid supported OP-TEE configuration reaches the violating history.
2. The attacker starts in the documented Normal-World threat model; no hostile
   TA/SP is required for a bounty-focused candidate.
3. A stock vulnerable build reproduces the violation.
4. A negative control or candidate fix removes the violation.
5. The result changes Secure-World confidentiality, integrity, authentication,
   authorization, or code/data identity—not only availability or a harness
   assertion.
6. The minimized history and complete logs distinguish the root cause from a
   superficially similar duplicate.
