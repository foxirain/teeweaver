# Boundary-guided state-machine engine

TEEWeaver v0.4 adds an experiment-synthesis layer above the v0.3 semantic
discovery engine. The two layers are complementary: v0.3 ranks and queries
observed histories, while v0.4 turns normalized security-boundary evidence
into falsifiable follow-up experiments.

## Boundary projection

`teeweaver.state_machine.observe_boundaries()` projects each relevant event
into a `BoundaryTuple`. The projection keeps security relationships while
discarding unstable identifiers such as PIDs, raw memory handles, and absolute
generation counters. Its dimensions include:

- protocol and abstract operation;
- actor/owner/receiver relation;
- lifecycle before and after the transition;
- generation and authorization relation;
- execution phase, fault family, and outcome class.

This lets two executions with different concrete handles contribute to the
same security coverage point. It also prevents identity churn from being
mistaken for exploration progress.

## Noise firewall

The v0.4 layer treats recovered retry failures as canonical retry noise.
Ordering comparisons require matching fault profiles, so an `AB` schedule
under one mutation is not compared with a `BA` schedule under a different
mutation. State-alias candidates must differ in normalized boundary coverage,
not only in opaque semantic-state hashes.

These filters reduce queue volume. They do not prove that the remaining
proposals are vulnerabilities.

## Experiment synthesis

`synthesize_experiments()` derives proposals only from relationships observed
in the supplied histories. Current proposal families include:

- cross-principal identity transposition;
- lifecycle epoch crossing;
- failure continuation;
- duplicate terminal transitions;
- reset/epoch crossing;
- ABA generation replay.

Each proposal contains its source evidence, mutations, required controls,
expected secure behavior, a falsifier, and `not_a_finding: true`. The queue
boosts proposals that target uncovered frontier properties and penalizes
already-covered relationships.

## Coverage and saturation

`coverage_report()` counts unique normalized boundary tuples and reports the
covered values for each dimension. A campaign is saturated only when the
configured trailing run window adds no new tuple. Saturation therefore means
that the current workload, adapter, and observation model have plateaued; it
does not mean the target has no remaining vulnerabilities.

The campaign driver retains v0.3 streaming novelty decisions and can also use
`--boundary-plateau N`. Either mechanism may stop an unproductive campaign,
and the emitted summary records the exact stop reason.

## Materialization

`tools/materialize_ffa_sequence.py` converts only the FF-A proposal families
that the public adapter can represent faithfully. Unsupported families fail
closed instead of being approximated through an unrelated transport.

The output is a line-oriented plan for
`instrumentation/ffa_sequence_probe/ffa_sequence_probe.c`. A plan references
existing Secure Partitions by UUID and can resolve endpoints, ping them, share
memory, send observed actions with a handle, reclaim a handle, and insert a
bounded scheduling delay. The probe logs every step as JSON and does not
contain a target patch or an expected vulnerable result.

## Crash evidence

The QEMU runner scans independent target logs for explicit Secure-World panic,
Secure-World data-abort, and Normal-World kernel-panic markers. Such evidence
is classified as `target-symptom`, ahead of a coincident runner timeout but
below an accepted invariant violation. A crash remains an experiment result
until causal controls, supported reachability, and security impact are shown.

## Responsibility boundary

TEEWeaver generates evidence and experiments. It does not assign CWE, CVSS,
exploitability, bounty severity, or vulnerability status. Candidate-specific
traces and coordinated-disclosure material must remain outside the public
repository until the affected project permits disclosure.
