# Duplicate firewall

TEEWeaver must not confuse a new schedule with a new vulnerability. Public
titles, CWEs, and changed line numbers are weak duplicate keys. The framework
uses a semantic fingerprint:

```text
(attacker boundary, required configuration, trigger history,
 violated invariant, protected asset, first unsafe transition, impact sink)
```

Two reports with different crashing instructions are still duplicates when
that tuple identifies the same unsafe transition. Conversely, code in the same
subsystem can be distinct when the violated lifetime, owner, generation, or
epoch contract differs.

## Promotion gate

A candidate does not enter the bounty queue until all of the following hold:

1. A stock supported build produces an end-to-end invariant violation, not
   merely a generated fault or rejected request.
2. Its semantic fingerprint is compared with `evaluation/known_cases.json`, OP-TEE
   advisories, release notes, fixed commits, and public issue/PR history.
3. The minimized history still violates the property after removing operations
   associated with the closest known case.
4. The first unsafe transition and the security consequence are both different
   from the closest known case, or the report clearly demonstrates an
   incomplete/bypassable fix.
5. A clean control and, where possible, the known fix or a candidate fix remove
   the violation.

This cannot detect private reports held by a bounty program. It reduces public
and conceptual duplicates; it does not promise uniqueness against an embargoed
queue.

## Known-positive uses

- The malicious-supplicant fTPM advisory is a regression oracle for hostile REE
  return codes and TA-restart consequences.
- The FF-A shared-memory teardown UAF is a concurrency/lifetime ground truth.
- The subkey rollback advisory is an authentication-metadata/epoch ground
  truth.
- The concurrent TA-context UAF is a scheduler ground truth, but its signed-TA
  prerequisite keeps it outside the primary Normal-World bounty lane.

Known cases are evaluation data. Rediscovering them is a successful framework
test, not a reportable result.

The generator, scheduler, and runtime oracles must not import this registry.
It is opened only after a candidate has been minimized, or after a framework
version has been frozen for a retrospective benchmark run.

## Duplicate-resistant frontier

The preferred target is not “another malformed RPC.” It is a previously
unobserved accepted transition such as:

- Secure World consuming response bytes bound to another live request;
- use of an earlier SHM generation after release and allocator reuse;
- FF-A reclaim while a receiver reference is live, or accepted retrieve/access
  of a reclaimed generation, with a first unsafe transition distinct from the
  published teardown UAF;
- one TA, VM, or SP consuming another owner's resource without an explicit
  share;
- authenticated bytes or metadata changing before their security-sensitive
  use;
- a failed/cancelled operation publishing an object consumed later; or
- an acknowledged persistent update reverting across a precisely controlled
  reset epoch.

These fingerprints are temporal and relational. They are less likely to be
produced by independent single-function static scans, while remaining directly
testable and falsifiable.
