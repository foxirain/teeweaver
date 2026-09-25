# Research position and literature map

Last reviewed: 2026-09-26.

This document states a falsifiable research gap. It does not claim novelty
merely because no identical project name was found.

## Existing systems and what they contribute

| Work | Primary capability | What TEEWeaver reuses | Gap relevant to this project |
|---|---|---|---|
| [Iago Attacks, ASPLOS 2013](https://www.cs.utexas.edu/~hovav/dist/iago.pdf) | Shows that a malicious OS can compromise protected applications through carefully chosen system-call results | Core adversarial-host principle: syntactically valid untrusted-service results are security inputs | Does not provide an OP-TEE history generator or temporal RPC/SHM oracle |
| [BesFS, USENIX Security 2020](https://www.usenix.org/conference/usenixsecurity20/presentation/shinde) | Specifies and proves a filesystem interface safe against a completely malicious OS | Derive executable state invariants from an untrusted-service specification | SGX/POSIX filesystem focus; TEEWeaver covers OP-TEE's broader RPC, generation, scheduling, and reset histories and tests an existing implementation rather than replacing it |
| [SmashEx, CCS 2021](https://www.shwetashinde.org/publications/smashex_ccs21.pdf) | Demonstrates that asynchronous OS-enclave exception entry can violate enclave assumptions | Treat asynchronous entry/resume and attacker-controlled scheduling as first-class security input | SGX exception mechanism differs from OP-TEE's SMC/RPC suspension model |
| [PARTEMU, USENIX Security 2020](https://www.usenix.org/conference/usenixsecurity20/presentation/harrison) | Emulates four real TrustZone OSes, including OP-TEE, to enable dynamic TA analysis | Full-system TEE execution and introspection | Primarily enables TA analysis; it does not define adversarial REE/RPC history invariants |
| [TEEzz, IEEE S&P 2023](https://purs3lab.github.io/files/teezz.pdf) and [artifact](https://github.com/HexHive/teezz-fuzzer) | Infers TA message types/dependencies and fuzzes stateful TA interaction sequences on devices | Sequence seeds, dependency preservation, state reset | Mutates TA-facing interactions; does not systematically perturb the RPC responder, secure-thread resume order, SHM generations, and reset epoch as one history |
| [SyzTrust, IEEE S&P 2024](https://arxiv.org/abs/2309.14742) and [artifact](https://github.com/SyzTrust/syztrust) | State-aware Trusted OS fuzzing using ETM/RTT and a debug probe | State coverage in addition to branch coverage | Targets resource-constrained Trusted OSes and assumes a TA can be installed plus ETM access; its published model is not an adversarial Linux/`tee-supplicant` state machine |
| [Trusty-StateFuzz, JSEP 2026](https://onlinelibrary.wiley.com/doi/10.1002/smr.70085) | Models TEE-kernel state variables and uses state coverage/N-gram generation | Evidence that equal code coverage can hide different security states | State is internal program-variable state; TEEWeaver's proposed feedback is cross-boundary identity/lifetime/epoch state, observable independently of a particular internal variable layout |
| [Fuzzing trusted execution environments with Rust, Computers & Security 2025](https://doi.org/10.1016/j.cose.2024.104196) | Generates stateful TEE API-call sequences, preserves object dependencies, and customizes QEMU for efficient execution | API-specification-driven sequence generation and object reuse are relevant baselines | Exercises the Trusted OS API from generated clients; it does not model a malicious supplicant's response binding, REE-owned SHM generations, or cross-reset freshness as one history |
| [TeeDFuzzer, Electronics 2025](https://doi.org/10.3390/electronics14081674) | Infers data dependencies between Trusted Kernel system calls and fuzzes improved call sequences through custom CA/TA components | Dependency-aware sequence generation is a required comparison | Its primary mutation surface is the TA-mediated Trusted Kernel syscall interface and its reported oracle is crashes; TEEWeaver perturbs the untrusted service/scheduling side and checks non-crashing relational properties |
| [Multi-Interface Analysis-Based Fuzzing Scheme for OPTEE, ICCIBDA 2025](https://doi.org/10.1145/3746709.3746868) | Seeds from `xtest`, traces multiple OP-TEE interfaces, and applies coverage-guided kernel fuzzing | `xtest`-derived workloads and multi-interface tracing are direct experimental baselines | The published description focuses on syscall/interface inputs and coverage, not accepted malicious-REE response histories or reset/ownership oracles |
| [Freesia, ISSTA 2025](https://conf.researchr.org/details/issta-2025/issta-2025-papers/89/Freesia-Verifying-Correctness-of-TEE-Communication-with-Concurrent-Separation-Logic) and [artifact](https://github.com/FLZeng/Freesia) | Formally verifies a concurrent TEE communication design and implements an OP-TEE prototype | Its communication invariants and concurrency proof obligations should inform oracle review | It verifies and prototypes a designed communication mechanism; TEEWeaver dynamically searches an existing OP-TEE deployment's adversarial RPC/SHM/reset histories |
| [LightEMU](https://arxiv.org/abs/2311.09532) | Hardware-assisted, feedback-driven TA fuzzing using CoreSight | Efficient execution/coverage backend option | Focuses on TA fuzzing throughput, not adversarial RPC semantics |
| [TÄMU, 2026](https://www.nebelwelt.net/blog/2026/0521-taemu.html) | Emulates Trusted Applications at the GlobalPlatform API layer and prioritizes API implementation using static reachability | API-layer emulation can become a high-throughput TA-side baseline | Its target is TA execution at the GP API boundary; it does not execute or perturb the real Linux driver/`tee-supplicant`/Secure-World suspend-resume protocol |
| [OP-TEE AFL syscall fuzzer](https://github.com/Keysight/optee_fuzzer) | Proxy TA generates OP-TEE system calls from AFL inputs | Baseline for syscall/parser-visible defects | Scanner-shaped, single-interface input mutation; no cross-world history oracle |
| [GlobalConfusion, USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/busch-globalconfusion) | Finds a specification-level class of TA type-confusion errors and proposes GPCheck | Demonstrates the value of specification-derived invariants instead of isolated crash hunting | Checks command/parameter type contracts; TEEWeaver targets temporal identity and lifetime contracts |
| [OP-TEE malicious-supplicant/fTPM advisory, 2025](https://github.com/OP-TEE/optee_os/security/advisories/GHSA-f35r-hm2m-p6c3) | Shows a hostile REE return code can panic secure-storage TAs and reset kept-alive fTPM state | Direct evidence that a malicious `tee-supplicant` is a productive, bounty-relevant threat model and that TA restart can create confidentiality/integrity impact | A known single-response error-path flaw; TEEWeaver must explore new multi-request, lifetime, byte-identity, and epoch histories rather than rediscover it |
| [OP-TEE FF-A shared-memory teardown UAF, 2026](https://github.com/OP-TEE/optee_os/security/advisories/GHSA-332c-xr93-849m) | A non-secure FF-A flow races share/lend traversal against reclaim/relinquish and reaches Secure-World UAF | High-severity ground truth for schedule/lifetime testing and a concrete evaluation seed | The published `sp_mem_remove()` locking defect is known and excluded from new-finding counts |
| [OP-TEE subkey rollback advisory, 2026](https://github.com/OP-TEE/optee_os/security/advisories/GHSA-fhcg-pp56-8v75) | Dropped subkey-version metadata prevents the rollback database from advancing | Ground truth for authenticated-metadata continuity and epoch/freshness oracles | Static data-flow bug with a known fix; the framework targets other verify-to-use and reset histories |
| [OP-TEE concurrent TA-context UAF, 2026](https://github.com/advisories/GHSA-p84g-83m7-53p6) | Concurrent sessions corrupt a shared TA context's VM-region lifetime | Ground truth for PCT schedule depth and lifetime-oracle evaluation | Requires a specially signed concurrent TA, so it is not the primary Normal-World bounty lane and its known root cause is excluded |
| [AFLNet](https://github.com/aflnet/aflnet) | Uses protocol response state plus code coverage for stateful network fuzzing | Sequence mutation and protocol-state feedback | Response codes are not sufficient to encode secure-thread, memory-generation, and reset identity |
| [CHESS](https://www.microsoft.com/en-us/research/publication/chess-a-systematic-testing-tool-for-concurrent-software/) | Systematically explores controlled concurrent schedules | Yield-point control, reproducibility, bounded schedule exploration | Assumes scheduler control within a program; TEEWeaver must control a cross-world protocol mediated by SMC, Linux, and a multithreaded supplicant |
| [PCT](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/paper-83.pdf) | Samples low-depth concurrency bugs with a probability guarantee | Priority-change-point scheduler and the notion of bug depth | Needs TEE-specific actors and yield points |
| [QEMU record/replay](https://www.qemu.org/docs/master/system/replay.html) | Replays nondeterministic VM inputs using `icount` and snapshots | Deterministic reproduction and reverse debugging | Replays a known run; it does not decide which security-relevant histories to generate or whether a non-crashing result is wrong |
| [Nyx](https://github.com/nyx-fuzz/Nyx) | Fast full-VM snapshot fuzzing and structured interactive inputs | Long-term high-throughput snapshot backend design | Current public fast path is x86/KVM-centric; OP-TEE QEMU-v8 needs an Arm-compatible path |
| [Fuzzware, USENIX Security 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/scharnowski) | Infers how firmware consumes MMIO inputs to build precise models | Input-space reduction by modeling only values that affect control/data | Models hardware inputs for monolithic MCU firmware, not cross-world RPC ownership |
| [FirmWire](https://github.com/FirmWire/FirmWire) | Full-system baseband rehosting with injectable fuzz tasks and stateful crash logs | Preserve complete multi-input histories and inject at native message boundaries | Its target and security boundary are different; its stateful log is not an OP-TEE invariant checker |
| [Jepsen](https://github.com/jepsen-io/jepsen) | Generates concurrent histories under faults and checks them against a model | History-first checking and fault composition | Database consistency models must be replaced by TEE security models |

## Working research gap

The evidence above supports, but does not yet prove, this narrower statement:

> Existing published TEE fuzzers primarily mutate TA/system-call inputs or
> track internal code/program state. Existing concurrency and history checkers
> are not specialized to OP-TEE. We have not found a system that treats a
> malicious REE RPC service, secure-thread suspension/resumption, shared-memory
> generation, authenticated-byte identity, and reset epoch as one generated and
> machine-checked OP-TEE security history.

The gap must survive a systematic literature review and artifact comparison
before a paper claims novelty.

The 2025 malicious-supplicant advisory and 2026 FF-A UAF are especially
important controls: they show that the chosen threat boundary and temporal
lifetime bugs are not hypothetical. They also create a strict duplicate
boundary. TEEWeaver may use their vulnerable/fixed revisions as ground truth,
but it may not count either root cause as a new result.

## Theoretical lens

TEEWeaver treats OP-TEE RPC as an Iago-attack interface and each complete run as
a concurrent history. That choice follows three facts:

1. OP-TEE explicitly relies on Normal World for services and shared-memory
   allocation even though Normal World is untrusted.
2. [OP-TEE's scheduling documentation](https://optee.readthedocs.io/en/3.19.0/architecture/core.html)
   states that trusted threads suspend for RPC and are effectively scheduled by
   their Normal-World caller; this makes schedule selection attacker-relevant.
3. An RPC result can be locally well-typed yet globally wrong for its request,
   owner, memory generation, authenticated bytes, or reset epoch. Those are
   relational/temporal properties and cannot be decided from a return value or
   a single function in isolation.

The checker is therefore a small runtime reference monitor over histories. It
does not attempt to prove the whole implementation correct; it searches for a
counterexample to explicit safety properties.

## Proposed contribution

TEEWeaver combines four ideas that are individually established but not known
to be combined for this boundary:

1. **Protocol-valid adversarial REE.** Generate valid OP-TEE client/RPC flows,
   then delay, cross-bind, replay, truncate, fail, or mutate only at legal yield
   points.
2. **Semantic state coverage.** Retain histories based on a tuple of live RPC
   identities, secure actor, session, SHM identifier and generation, object
   digest stage, reset epoch, and injected fault—not solely on executed edges.
3. **External security oracles.** Check identity, lifetime, authentication/use,
   failure atomicity, owner isolation, and persistence freshness even when the
   target returns success and never crashes.
4. **Deterministic history reproduction.** Record the generated history and use
   QEMU `icount`/record-replay plus delta minimization to make rare
   interleavings reportable.

## What would invalidate the thesis

- A prior artifact already generates the same cross-world state tuple and
  checks equivalent invariants.
- The relevant histories cannot be controlled without modifying the vulnerable
  secure-world logic, making results non-reproducible on stock builds.
- Semantic state coverage does not find more seeded or real faults than edge
  coverage plus random delay under equal time budgets.
- Every discovered violation is already permitted by the OP-TEE/GlobalPlatform
  contract or cannot produce a concrete Secure-World security impact.
