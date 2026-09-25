# Results v0.2 public research preview

## Public validation scope

TEEWeaver v0.2.0-alpha has been exercised against an upstream OP-TEE QEMU-v8
environment using clean controls, protocol-derived fault campaigns, stock FF-A
test SPs, and reset/storage ground truth. The public package contains the
framework and a synthetic seven-run corpus that deterministically exercises
all nine dynamic element classes.

Run:

```sh
python3 tools/mine_elements.py
```

The bundled corpus should produce elements for:

- hidden global resource scope;
- non-commutative action-pair candidates;
- failure-residual state;
- ownership transfer;
- ABA identity reuse;
- hidden serialization domains;
- reset-surviving state;
- non-terminating transitions; and
- state aliasing.

The examples are intentionally synthetic and are not vulnerability findings.
Their purpose is to make the public research preview executable without
publishing raw traces from coordinated or ongoing security research.

## Disclosure boundary

Candidate-specific raw histories, exact endpoint/action details, and unfinished
root-cause work are excluded from this public preview. This separation does not
change the miner or its tests: only the private evidence corpus is withheld.

An element score prioritizes follow-up experiments. It is not CVSS, security
severity, exploitability, novelty, or bounty probability.

