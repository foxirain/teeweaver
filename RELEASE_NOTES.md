# TEEWeaver v0.2.0-alpha

TEEWeaver is a research preview for mining history-dependent semantic elements
across the OP-TEE REE/Secure-World boundary.

The release includes:

- nine dynamic element extractors;
- RPC, SHM, reset/storage, and FF-A event support;
- an AArch64 `LD_PRELOAD` interposer for public Linux TEE/FF-A interfaces;
- stateful invariant oracles and a separate promotion gate;
- a dependency-free synthetic corpus demonstrating all element classes;
- 39 self-contained unit tests; and
- code/evidence freeze tooling.

The release does not claim a new OP-TEE vulnerability. Candidate-specific
evidence from ongoing security research is not included.

