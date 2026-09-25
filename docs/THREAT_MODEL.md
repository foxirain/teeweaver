# Threat model

## Primary attacker

The primary attacker controls Normal World to the degree promised by the TEE
security model. Depending on the experiment this is one of:

- a malicious client process using the public Linux TEE API;
- a malicious or compromised `tee-supplicant`;
- a malicious Normal-World process or kernel driving the public
  `arm_ffa_user` share/message/reclaim ABI;
- a compromised REE kernel capable of choosing shared pages and SMC timing;
- a reset/power adversary for storage experiments.

The attacker cannot directly read or write private Secure-World memory, forge
the OP-TEE signing root, or patch the vulnerable Secure-World binary.

The included FF-A lifecycle probe talks only to SPs already present in the
upstream QEMU image. It is an instrumentation/evaluation actor, not authority
to assume an attacker-controlled production SP. A bounty candidate must still
show that hostile Normal World alone reaches the unsafe accepted transition.

## Protected assets

- private TA/core memory and cryptographic material;
- identity and ownership of sessions, TAs, SPs, and RPC results;
- authenticated code/data identity between verification and consumption;
- integrity and freshness of secure persistent objects;
- Secure-World control flow.

## Non-goals for the first paper

- microarchitectural side channels;
- physical probing, voltage/clock glitching, or Rowhammer;
- arbitrary bugs confined to attacker-authored TAs;
- proving OP-TEE correct;
- classifying a harness-only assertion as a vulnerability.

## Bounty filter

The Arm Trusted Firmware program has historically treated findings requiring a
malicious TA or Secure Partition less favorably than Normal-World-originating
boundary failures. Therefore TEEWeaver prioritizes an untrusted REE origin and
a concrete Secure-World consequence. SP-only results remain useful for a paper,
CVE, or hardening contribution but are a secondary bounty queue.
