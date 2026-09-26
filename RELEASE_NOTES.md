# TEEWeaver v0.3.0-alpha

TEEWeaver v0.3.0-alpha is a research preview of a dynamic semantic discovery
engine for OP-TEE. It turns multi-run Normal- and Secure-World observations
into bounded, evidence-backed experiment targets without assigning CWE, CVSS,
exploitability, or vulnerability verdicts.

## Highlights

- Extract identity-independent semantic features across operations,
  principals, endpoints, sessions, resource lifetimes, values, and reset
  epochs.
- Rank histories by marginal and relational novelty while retaining clean
  controls as comparison anchors.
- Mine pairwise contrasts, outcome associations, feature co-occurrences, and
  typed semantic graphs across a corpus.
- Maintain a resumable streaming discovery index with explicit retain and
  discard decisions for long-running QEMU campaigns.
- Produce bounded, provenance-hashed AI context packs for a selected run,
  feature, contrast, or queue rank.
- Normalize existing OP-TEE `secure.log` records and strict `TWTRACE` JSON
  markers with exact source-line, parser-rule, and confidence provenance.
- Keep Normal- and Secure-World observations in independent ordering domains
  unless the trace provides a valid shared ordering relation.
- Recover loader-store fallback, mapping aliases, call completion, refcount
  transitions, FF-A resurrection, terminal follow-up, and secure-thread wait
  transitions.
- Profile unmodeled Secure-World callsite shapes so observation coverage can be
  expanded without selecting a known vulnerability as the target.

## Validation

- 71 dependency-free unit tests cover the discovery engine, streaming index,
  secure-log normalization, ordering-domain isolation, existing invariant
  oracles, and legacy element mining.
- The bundled seven-run public corpus produces 72 semantic features, three
  contrasts, and ten legacy dynamic elements without candidate-specific or
  embargoed evidence.
- The release workflow compiles all Python sources, builds both source and
  wheel distributions, installs the wheel, exercises the command-line entry
  point, runs the public discovery demonstrations, and verifies a source
  freeze.
- The framework has also been exercised against the pinned upstream OP-TEE
  QEMU-v8 environment. Those experiments include clean controls, defensive
  negative controls, FF-A memory lifecycles, concurrent TA activity, and reset
  persistence checks.

## Scope and limitations

This release does not claim a new OP-TEE vulnerability. A high-ranked history
or extracted relationship is an experiment priority, not a security finding.
Promotion still requires a reproducible invariant violation, causal controls,
affected supported configurations, and independent review.

The native secure-log parser intentionally recognizes only modeled record
shapes. Unparsed lines remain visible through the gap profiler and are not
treated as irrelevant. Cross-stream temporal relationships are not inferred
from file position or unrelated timestamps.

Candidate-specific traces and private research results are excluded from the
release artifacts.

## Compatibility

- Python 3.11 or later
- OP-TEE QEMU-v8 for the documented end-to-end environment
- No runtime Python dependencies

The Python package version is `0.3.0a1`; the corresponding repository release
tag is `v0.3.0-alpha`.
