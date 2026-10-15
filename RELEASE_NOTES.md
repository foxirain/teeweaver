# TEEWeaver v0.4.0-alpha

TEEWeaver v0.4.0-alpha closes the loop between observed OP-TEE histories and
adversarial experiment design. It retains the v0.3 discovery bundle, bounded
query, streaming novelty index, and secure-log normalization interfaces while
adding a normalized security-boundary model and falsifiable experiment queue.

## Highlights

- Project events into identity-renaming-resistant boundary tuples spanning
  protocol, operation, principal relation, lifecycle, generation,
  authorization, phase, fault family, and outcome.
- Measure boundary coverage and trailing-window saturation without treating
  PID, handle, or absolute generation churn as progress.
- Synthesize cross-principal, cross-lifetime, failure-continuation,
  duplicate-terminal, reset, and ABA experiments from observed evidence.
- Attach required controls, expected secure behavior, falsifiers, source
  evidence, and `not_a_finding: true` to every proposal.
- Prioritize uncovered security-frontier targets and expose adapter gaps
  separately from executable proposals.
- Filter recovered retry noise, mismatched-fault ordering comparisons, and
  state-hash differences that do not change normalized boundary coverage.
- Materialize supported FF-A proposals as line-oriented plans for a generic
  `arm_ffa_user` sequence probe; unsupported families fail closed.
- Preserve explicit target panic and abort evidence separately from runner
  timeouts without promoting either to a vulnerability verdict.
- Retain v0.3 semantic discovery and add optional boundary-plateau stopping to
  the existing QEMU campaign driver.

## Validation

- 88 dependency-free unit tests cover both the retained v0.3 interfaces and
  the v0.4 boundary model, synthesis queue, materializer, noise filters, and
  target-symptom classification.
- CI compiles all Python sources, builds and installs the wheel, exercises the
  public v0.3 discovery pipeline, runs v0.4 trace and corpus synthesis demos,
  validates public evidence, and verifies a source freeze.
- The bundled public corpus and histories are synthetic or previously public
  controls. Candidate-specific traces, reports, and coordinated-disclosure
  material are excluded.

## Scope and limitations

TEEWeaver proposals are experiment requests, not security findings. Boundary
coverage measures only the supplied workload, adapter, and observation model;
saturation does not imply that a target is secure. Promotion still requires a
reproducible invariant violation, causal controls, supported reachability,
concrete security impact, and independent review.

The FF-A materializer supports only proposal families that the public sequence
adapter can encode faithfully. Other proposals remain in the adapter backlog
until a protocol-specific executor and control are implemented.

## Compatibility

- Python 3.11 or later
- OP-TEE QEMU-v8 for the documented end-to-end environment
- No runtime Python dependencies

The Python package version is `0.4.0a1`; the intended repository release tag
is `v0.4.0-alpha`.
