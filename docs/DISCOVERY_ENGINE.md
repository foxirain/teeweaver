# Semantic discovery engine

## Responsibility boundary

TEEWeaver is a dynamic evidence backend for an AI researcher. It is optimized
to expose runtime relationships that are expensive or impossible to establish
from one source snapshot. It does not decide that a relationship is a security
vulnerability.

TEEWeaver owns:

- faithful event collection and provenance;
- identity-independent semantic feature extraction;
- cross-run comparison and corpus retention;
- deterministic, machine-readable experiment surfaces;
- bounded quality metadata such as unmatched calls and partial timestamps.

The downstream AI and researcher own:

- root-cause hypotheses and source-path selection;
- controlled falsification experiments;
- reachability and supported-platform analysis;
- exploitability, impact, duplicate, CWE, CVSS, and disclosure decisions.

The boundary is deliberate. Automatically turning a timeout, object reuse, or
rare history into a finding would recreate the false-positive behavior of an
ordinary scanner.

## Data flow

```text
QEMU / board / target process
        |
        v
append-only cross-world JSONL history
        ^
        +-- Normal-World JSONL (ordered domain A)
        +-- OP-TEE secure.log / TWTRACE (ordered domain B)
        |
        +--> per-run semantic feature profile
        |         |
        |         +--> online novelty index --> retain / discard from corpus
        |
        +--> multi-run differential mining
                  |
                  +--> greedy follow-up queue
                  +--> pairwise contrasts
                  +--> outcome associations
                  +--> feature co-occurrence
                  +--> typed semantic graph
                              |
                              v
                    downstream AI experiment
```

## Feature extraction

Feature identifiers are hashes of normalized relationship keys. Run labels,
sequence numbers, timestamps, and raw evidence locations do not affect a
feature identifier. Evidence references remain attached separately for source
navigation and reproduction.

Current families include:

| Family | Dynamic information represented |
|---|---|
| `operation` | observed operation plus protocol action/function/kind |
| `lifecycle` | ordered use of object, session, operation, request, call, key, thread, or context identities |
| `mapping-alias` | one virtual address observed in multiple mapping roles or identities |
| `cross-principal` | one resource identity observed by multiple runtime principals |
| `principal-handoff` | identity-independent ordered handoff path across principals |
| `identity-alias` | one runtime value occupying two protocol identity namespaces |
| `identity-binding` | request/claim and owner/receiver identity relationships |
| `byte-continuity` | verify-to-consume digest continuity |
| `call-completion` | issue/completion path and same- versus cross-principal completion |
| `failure-followup` | a failed transition followed by use of related state |
| `incomplete-transition` | a call issue with no observed completion |
| `overlap` | calls from distinct principals simultaneously in flight |
| `reentrancy` | one principal issuing a nested call while another remains in flight |
| `order` | bounded cross-principal ordering relationships |
| `retry-transition` | one action moving between explicit failure and success across retries |
| `progress-cycle` | a short contiguous action motif repeating at least three times |
| `refcount-transition` | local/global reference-count shapes for one runtime object |
| `resurrection-transition` | refcount observations surrounding an FF-A resurrection |
| `reset-epoch` | operations observed on opposite sides of reset |
| `epoch-continuity` | one resource identity observed on both sides of reset |
| `value-transition` | acknowledged-to-observed storage value continuity |
| `store-fallback` | one binary-load attempt traversing multiple TA stores and results |
| `terminal-followup` | a resource identity observed after free, reclaim, release, destroy, or cancel |
| `wait-transition` | secure-thread sleep/wake pairing, handoff, and unmatched boundary observations |
| `semantic-state` | a bounded stable sketch of state identifiers |
| `outcome` | externally visible workload result or runner error class |

Semantic-state identifiers are sampled with a deterministic bottom-k sketch of
512 entries per run. This preserves stable novelty feedback without allowing a
long execution to drown relationship features or inflate an artifact without
bound.

## Offline discovery bundle

Run:

```sh
python3 tools/discover_corpus.py \
  --corpus scenarios/mining-corpus-v0.2.json \
  --secure-logs \
  --budget 32 \
  --output artifacts/discovery-v0.3.json \
  --markdown artifacts/discovery-v0.3.md
```

The JSON schema is `teeweaver-discovery-v1`. It contains:

- all run profiles and trace-quality metadata;
- aggregate source/rule coverage and ignored secure-log line counts;
- a catalog of stable semantic features with exact evidence references;
- a greedy discovery queue;
- generic pairwise contrasts;
- feature/outcome association candidates;
- repeated cross-family feature co-occurrence;
- legacy v0.2 elements;
- a typed graph joining runs, principals, endpoints, operations, raw objects,
  object generations, generic resources, features, and elements; and
- a JSON contract an AI can use to request the next intervention and controls.

### Secure-log normalization and order domains

`--secure-logs` looks for `secure.log` beside each corpus trace. A corpus record
can use `"secure_log": true` to require that file, `false` to disable it, or a
relative filename to select another log. `tools/import_secure_trace.py` exposes
the same normalizer as a standalone JSONL converter.

Native rules cover stable debug records for TA/SP binary lookup and mapping,
SP endpoint binding and startup, FF-A object lookup/refcounts and resurrection,
SP retrieve/map results, session and TA-context destruction, TA panic cleanup,
RPC-cookie release, and secure-thread notification sleep/wake. Instrumented
builds may emit `TWTRACE {"op":"...", ...}` after a normal OP-TEE callsite
prefix for fields unavailable in native logs. Malformed structured markers are
rejected rather than silently downgraded.

Each event carries `source`, `order_domain`, `trace_rule`, `trace_confidence`,
and a source line. Sequence-dependent features are computed only inside one
ordering domain. The semantic graph, completion matching, retry transitions,
failure follow-ups, overlap detection, reset windows, and legacy temporal
miners all obey this constraint. Cross-source identities may still be compared
as unordered topology, but their file positions never imply happens-before.

`observation_coverage.secure_log` reports parsed and ignored lines. Parser
coverage is an audit boundary, not a completeness claim: an ignored line means
only that the current normalizer did not model it.

The gap profiler makes that boundary actionable without a benchmark-specific
rule list:

```sh
python3 tools/profile_secure_trace_gaps.py results/*/secure.log \
  --minimum-count 2 --limit 100 \
  --output artifacts/secure-trace-gaps.json
```

It removes UUIDs, addresses, and integer values from otherwise unmodeled
callsite messages, ranks the resulting shapes by frequency, and retains bounded
source examples. Frequency is explicitly not treated as impact. The report is
an observation-backlog input for AI/human selection of the next native rule or
structured tracepoint.

### Queue policy

Clean/control runs establish the ordinary feature union and are not placed in
the AI follow-up queue when treatment or diagnostic runs exist. Remaining runs
are selected greedily by:

- weighted marginal feature coverage;
- features absent from clean controls;
- inverse corpus frequency;
- relational-family diversity; and
- availability of a same-group contrasting run.

Priority scores have no fixed range. They are relative corpus-retention and
follow-up values, not severity or probability estimates.

### Generic differential mining

Pairwise contrasts are limited to runs in the same declared comparison group.
Visible `outcome` features are excluded from history similarity and association
inputs, preventing the result being predicted from a duplicate encoding of
itself. Histories are also projected into a non-temporal core so the engine can
separate schedule-only deltas from structural deltas.
The engine surfaces three shapes:

- same normalized history with different visible outcomes;
- nearby histories with different outcomes; and
- different semantic histories with the same visible outcome.

It additionally identifies same-core/different-schedule pairs, with and
without an outcome delta. Outcome associations are computed only within the
same declared comparison group and capped per feature family. Co-occurrences
are capped per family pair. These constraints prevent workload identity and
hundreds of low-level order features from crowding all other relationships out
of the AI frontier.

Association and co-occurrence records are explicitly correlational. Outcome
associations require at least two supporting and two absent histories to avoid
promoting a single observation as a strong pattern. Relationship bonuses are
bounded so hundreds of minor schedule-order features cannot overwhelm one
high-value identity or incomplete-transition relation.

## Streaming campaign index

For large campaigns, rebuilding a whole graph after each run wastes memory and
execution budget. `teeweaver-novelty-index-v1` processes one history at a time:

```sh
python3 tools/update_discovery_index.py \
  --corpus scenarios/mining-corpus-v0.2.json
```

The index stores feature support, bounded retained profiles, exact run
signatures, outcome signatures, and comparison groups. Its dispositions are:

- `retain`: adds semantic coverage or a controlled contrast;
- `discard-duplicate`: duplicates a retained feature/outcome signature;
- `discard-low-novelty`: adds insufficient weighted relationship coverage;
- `discard-control-redundant`: exceeds bounded control-variance sampling;
- `already-seen`: the same labelled history is already indexed; and
- `label-collision`: a label was reused for different content.

Every observed history contributes to support counts even when it is not
retained. This lets repeated ordinary behavior reduce the future novelty of the
same shape without storing every raw execution in the active corpus.

The QEMU campaign driver updates `discovery-index.json` and writes one
`discovery-decision.json` per run. An optional saturation budget can stop a
campaign after consecutive low-value executions:

```sh
python3 tools/run_campaign.py \
  --workload ffa-memory-lifecycle \
  --budget 100 \
  --novelty-stagnation 12
```

The option is disabled by default. A stopped campaign is not a proof that the
target has no remaining states; it means only that the selected generator has
stopped adding semantic coverage under the current index.

## AI experiment contract

The discovery bundle asks an AI to return:

```json
{
  "hypothesis": "a falsifiable statement",
  "selected_runs": ["run-label"],
  "target_features": ["feature-id"],
  "intervention": {
    "kind": "delay|repeat|schedule-order|identity-substitution|reset-replay|persistence-cut",
    "target": "action/resource/endpoint",
    "parameters": {}
  },
  "controls": ["one-change-only control"],
  "requested_observations": ["event or state required to distinguish explanations"]
}
```

This contract separates experiment choice from execution. The AI chooses what
relationship to test; TEEWeaver executes a supported intervention and returns
another provenance-preserving history.

### Bounded context queries

Large offline graphs should not be injected wholesale into an AI context. A
query selects one run, feature, contrast, or queue rank and returns only its
profiles, highest-value features, supporting elements, graph neighborhood,
experiment surface, and truncation counts:

```sh
python3 tools/query_discovery.py artifacts/discovery-v0.3.json \
  --rank 1 \
  --max-features 96 \
  --max-edges 128 \
  --max-elements 32 \
  --output /tmp/ai-context.json
```

The output schema is `teeweaver-ai-context-v1`. Evidence references and source
run labels are preserved, so bounding context does not turn a summary into an
untraceable claim. The pack records a canonical SHA-256 of the source bundle,
keeps focal runs separate from comparison runs, includes their bounded feature
delta, and reports every omitted feature, edge, element, profile reference,
queue reference, and surface value.

## Scaling properties

- Evidence collection per normalized feature is bounded.
- State sketches are bounded.
- Offline co-occurrence and contrast outputs are capped.
- The streaming index loads one history at a time.
- Control retention is bounded to three meaningful samples per comparison
  group.
- Existing indices can be resumed across independent campaigns.

The complete offline graph intentionally remains a heavier analysis mode. The
streaming index is the default feedback mechanism for long-running discovery.
