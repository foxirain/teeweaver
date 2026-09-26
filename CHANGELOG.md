# Changelog

All notable public changes are documented here.

## 0.3.0-alpha — 2026-09-26

- Add identity-independent semantic feature extraction across operations,
  lifetimes, principals, endpoints, sessions, requests, reset epochs, and
  storage values.
- Add a greedy novelty queue that uses clean controls as coverage anchors and
  prioritizes marginal, rare, and relational execution histories.
- Add generic pairwise contrasts, outcome associations, and cross-family
  co-occurrence mining without assigning vulnerability meaning.
- Add a typed semantic graph for runs, actors, endpoints, resource lifetimes,
  operations, features, and legacy v0.2 elements.
- Add a streaming novelty index for long-running campaigns with duplicate and
  low-novelty corpus filtering, bounded control-variance retention, and
  resumable state.
- Integrate per-run discovery decisions and optional novelty-saturation early
  stopping into the QEMU campaign driver.
- Add an explicit downstream-AI experiment contract while keeping CWE, CVSS,
  exploitability, and vulnerability verdicts outside the framework.
- Add bounded `run`, `feature`, `contrast`, and queue-rank context queries so
  an AI can consume a focused graph neighborhood instead of a multi-megabyte
  corpus bundle.
- Add runtime principal-handoff, identity-alias, nested-reentrancy,
  retry-transition, progress-cycle, and reset-continuity feature families.
- Remove visible-outcome leakage from history comparison and association
  mining; add non-temporal core projections for schedule-only contrasts.
- Add per-family and per-family-pair diversity quotas so order-heavy traces do
  not monopolize association and co-occurrence frontiers.
- Stratify outcome associations by declared comparison group to prevent
  workload identity from becoming a spurious predictor.
- Make AI context packs transitively bounded, provenance-hashed, and explicit
  about focal/comparison feature deltas and all truncation counts.
- Bound semantic-state sketches and optimize evidence deduplication for large
  corpora.
- Add optional OP-TEE `secure.log` ingestion and standalone normalization with
  exact rule, confidence, and source-line provenance.
- Add independent ordering domains so Normal- and Secure-World logs cannot
  create fabricated cross-stream order, overlap, completion, or lifecycle
  evidence.
- Recover secure scheduler sleep/wake, loader fallback, SP mapping/identity,
  FF-A refcount/resurrection, RPC release, session/context destruction, and
  panic-cleanup transitions from existing logs.
- Add mapping-alias, refcount-transition, resurrection-transition,
  call-completion, terminal-followup, wait-transition, and loader
  store-fallback discovery families plus aggregate observation-coverage
  metadata.
- Add an observation-gap profiler that normalizes and ranks unmodeled OP-TEE
  callsite shapes so parser expansion does not depend on a known vulnerability.

## 0.2.0-alpha — 2026-09-26

- Add nine-class, corpus-level dynamic element mining.
- Add AI-consumable JSON and human-readable Markdown reports.
- Add relation graphs, falsifiers, next experiments, and root-cause hints.
- Add pre-call/completion correlation for FF-A message and reclaim ioctls.
- Record meaningful FF-A failure `errno` values and discard stale success
  values.
- Add bounded workload timeout overrides for nontermination experiments.
- Add a seven-run synthetic public corpus covering all nine element classes.
- Preserve the separation between stimuli, dynamic elements, invariant
  violations, and disclosure-ready findings.

This is a research preview. Element scores are experiment priorities, not
security severities.
