# Dynamic element mining

This v0.2 layer remains supported. The v0.3 discovery engine in
`docs/DISCOVERY_ENGINE.md` consumes the same histories, retains these named
elements, and adds identity-independent semantic features, generic contrasts,
an online novelty index, and an AI experiment contract. Neither layer issues a
vulnerability verdict.

## Purpose

The v0.2 miner produces reusable evidence for an AI researcher. It does not
decide that a vulnerability exists. Its job is to expose dynamic structure that
is easy to lose when analysis is restricted to source snippets, crashes, or a
single successful/failed test.

Run it with:

```sh
python3 tools/mine_elements.py \
  --corpus scenarios/mining-corpus-v0.2.json \
  --output artifacts/elements-v0.2.json \
  --markdown artifacts/elements-v0.2.md
```

The corpus can contain ordinary result directories, reset `epoch-history`
files, or an expandable campaign directory. Each record declares a label,
role, and comparison group. This keeps clean controls, diagnostics, injected
treatments, and intentional ground truth distinguishable.

## Nine extractors

| Kind | Runtime relation extracted | Promotion question |
|---|---|---|
| `hidden-global-resource` | one identity/allocator spans principals | can one actor influence another actor's resource? |
| `non-commutative-action-pair` | AB and BA orders co-vary with outcome | does order alone cause the delta under identical inputs? |
| `failure-residual-state` | state is reused after a failed transition | did failure publish a partial mutation? |
| `ownership-transfer` | owner and receiver differ over one lifetime | can authorization/lifetime be confused at handoff? |
| `aba-reuse-cycle` | raw identity returns at a new generation | can a stale operation bind to the new lifetime? |
| `hidden-serialization-domain` | independent actors contend for one slot | can blocking/error state cross endpoint boundaries? |
| `reset-surviving-state` | acknowledged state is observed after reset | is freshness anchored outside replayable state? |
| `non-terminating-transition` | pre-call marker lacks a matching return | which layer owns the unbounded wait, and is it attacker-triggerable? |
| `state-aliasing` | same result hides different semantic histories | which later observation separates the aliased states? |

Order candidates are intentionally correlational. Different fault plans or
unobserved inputs can cause the outcome delta. The generated element tells the
next agent to construct controlled AB/BA runs; it does not claim causation.

## Output contract

Every element contains:

- a stable content-derived ID, kind, score, and confidence;
- a narrowly worded claim;
- exact run/event evidence;
- an explanation of why runtime history was required;
- alternative explanations and explicit falsifiers;
- next experiments and source-level root-cause hints; and
- `not_a_vulnerability: true`.

The 0–100 score is a follow-up priority based on evidence strength,
repetition, and dynamic specificity. It is not CVSS, security severity,
exploitability, novelty, or bounty probability.

The report also includes a relation graph connecting elements, runs,
principals, and objects. An AI can use the graph to choose experiments without
being shown a preselected vulnerable function.

## Promotion boundary

An element may be promoted only after a controlled experiment isolates the
causal transition and an existing security oracle shows unauthorized
confidentiality, integrity, or meaningful availability impact. A timeout,
`EBUSY`, state novelty, or object reuse is not sufficient by itself.

For a security report, repeat the final trigger against an unmodified target,
add a passing negative/fixed control, minimize the history, and apply
`tools/promote_candidate.py`.
