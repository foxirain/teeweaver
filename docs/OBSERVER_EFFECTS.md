# Observer-effect register

## OE-001: synchronous client ioctl tracing changes cancellation behavior

- Target: upstream QEMU-v8 build, `xtest 1009`.
- Control: supplicant instrumentation active, client tracing disabled.
  Result: 14/14 subtests pass and process status is zero.
- Treatment: the same environment with client `TEE_IOC_INVOKE` /\
  `TEE_IOC_CANCEL` tracing enabled. Result: subtest 1009.3 returns
  `TEEC_SUCCESS` instead of `TEEC_ERROR_CANCEL`.
- Decision: this is not an OP-TEE finding. Client tracing is disabled by
  default, non-supplicant SHM events are excluded by process-role scoping, and
  cancellation is marked quarantined in the coverage matrix.
- Re-entry criterion: a ring-buffer, kernel-tracepoint, or emulator adapter
  must reproduce the clean result across repeated A/B controls before the
  cancellation oracle can be used for discovery.

The raw controls are stored under:

- `results/validation-cancellation-ab-control-v1`
- `results/validation-cancellation-timestamp-v1`

This register is part of the framework's false-positive policy: any adapter
that changes a security-sensitive schedule is removed from discovery mode.
