# Storage epoch probe

`storage_probe` is a Normal-World client for the upstream signed OP-TEE test
storage TA. It writes or reads one fixed persistent object and emits an
unambiguous acknowledgement/observation token. It does not add a custom TA or
modify Secure World.

Its purpose is to give the reset backend two semantic markers:

```text
TEEWEAVER_STORAGE_ACK value_hex=...
TEEWEAVER_STORAGE_OBSERVE value_hex=...
```

The reset campaign must preserve `/var/lib/tee` into an experiment-specific
host directory after the acknowledged write and restore it before the first
storage RPC of the next boot. It records the exact cut point and durable file
image. A differing post-reset value
is a candidate only if the write was acknowledged, the preserved image belongs
to the same experiment, and a no-cut control retains the acknowledged value.
