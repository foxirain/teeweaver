# FF-A lifecycle probe

`ffa_probe` is an unprivileged Normal-World actor for the public
`arm_ffa_user` ABI used by the upstream QEMU Trusted Services configuration.
It does not patch an SP or OP-TEE.  A run resolves one existing SP UUID and
executes a balanced memory lifecycle with both negative and positive controls:

1. share, retrieve twice, and read;
2. relinquish once and prove early reclaim is rejected;
3. relinquish the second reference and prove reclaim succeeds;
4. prove retrieve of the reclaimed handle is rejected.

Two instances can target different stock test SPs concurrently.  This gives
the framework independent Normal-World actors without relying on the singleton
state of one SP test endpoint.
