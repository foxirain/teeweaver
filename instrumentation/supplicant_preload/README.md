# `tee-supplicant` interposer

This library observes and perturbs the public Linux supplicant ABI without
modifying OP-TEE OS. It is meant for the QEMU guest's AArch64
`tee-supplicant`, not the host.

## Build

```sh
make OPTEE_ROOT=/path/to/optee-qemu-v8
file libteeweaver.so
```

## Install into the existing QEMU Buildroot target

The recommended path is the top-level automated runner, which places the
library in a per-run 9P export and instruments the first boot-time supplicant:

```sh
cd /path/to/teeweaver
PYTHONPATH=src python3 tools/run_qemu_experiment.py --workload baseline
PYTHONPATH=src python3 tools/run_qemu_experiment.py --workload load-ta-swap
```

For manual experiments, copying into `out-br/target` is also possible.

Copying into `out-br/target` is intentionally not automatic because that tree
may contain researcher changes:

```sh
install -m 0755 libteeweaver.so \
  /path/to/optee-qemu-v8/out-br/target/usr/lib/libteeweaver.so
```

Rebuild the rootfs, then stop the normal supplicant and run it in the guest:

```sh
TEEWEAVER_TRACE=/tmp/teeweaver.jsonl \
LD_PRELOAD=/usr/lib/libteeweaver.so \
/usr/sbin/tee-supplicant
```

The default trace path is `/tmp/teeweaver.jsonl`.

## FF-A mode

Set `TEEWEAVER_TRACE_FFA=1` only for a Normal-World process using the public
`arm_ffa_user` debugfs ABI. Accepted test-SP transitions are converted to
`ffa_share`, `ffa_retrieve`, `ffa_relinquish`, `ffa_reclaim`, and `ffa_access`
events. The merge layer translates process-local observation counters into a
global generation per kernel handle.

Every FF-A message and reclaim emits `ffa_call_issue` immediately before the
real ioctl and a completion event afterwards. Both carry a stable call ID;
completions also record `ioctl_errno`. A bounded run can therefore distinguish
"the workload never reached this call" from "the call was issued and never
returned" without modifying Linux, OP-TEE, or an SP.

Set `TEEWEAVER_FFA_FAULT` to one rule per process:

```text
ffa_delay:<action-or-reclaim>:<occurrence>:<microseconds>
ffa_duplicate:<action-or-reclaim>:<occurrence>
ffa_flip_handle:<action-or-reclaim>:<occurrence>:<xor-mask>
```

Examples:

```sh
# Repeat the first observed synthetic action (action 42).
TEEWEAVER_FFA_FAULT=ffa_duplicate:42:1

# Substitute one bit in the second reclaim handle.
TEEWEAVER_FFA_FAULT=ffa_flip_handle:reclaim:2:0x1
```

These are attack stimuli. They become candidates only if the target accepts a
forbidden lifetime/owner transition; an xtest failure alone is not a finding.

## One-fault grammar

Set `TEEWEAVER_FAULT` to one rule per run:

```text
delay:<rpc-func>:<occurrence>:<microseconds>
force_ret:<rpc-func>:<occurrence>:<return-value>
swap_pair:<rpc-func>[:<start-occurrence>]
flip_memref:<rpc-func>:<occurrence>:<param-index>:<byte-offset>:<xor-mask>
```

`*` may replace the RPC function. Examples:

```sh
# Delay the first REE-FS response by 100 ms.
TEEWEAVER_FAULT=delay:2:1:100000

# Force the third LOAD_TA response to TEEC_ERROR_GENERIC.
TEEWEAVER_FAULT=force_ret:0:3:0xffff0000

# Wait for two concurrent REE-FS replies and exchange their async request IDs.
TEEWEAVER_FAULT=swap_pair:2:100

# Flip the first byte of parameter 2 on the first REE-FS response.
TEEWEAVER_FAULT=flip_memref:2:1:2:0:0x01
```

`swap_pair` makes one 100 ms fail-open pairing attempt per run. It requires two
concurrent requests with the same parameter count and the asynchronous meta
parameter used by current `tee-supplicant`. A failed attempt does not delay
every later reply. Exchanging IDs and changing a registered response buffer are
within the capability of a malicious supplicant. A target-specific workload
must add end-to-end content tokens so the framework can prove whether OP-TEE
consumed the wrong response; the interposer alone is not vulnerability proof.

Every RPC trace includes `ioctl_result`. A reply is considered delivered by
the framework only if the real `TEE_IOC_SUPPL_SEND` call returned a
non-negative value.

The library contains an experimental client-side `TEE_IOC_INVOKE` /
`TEE_IOC_CANCEL` trace mode, enabled only with `TEEWEAVER_TRACE_CLIENT=1`.
It is quarantined: A/B testing showed that enabling it changes the outcome of
the official cancellation test. It must not be used for discovery until a
low-observer-effect replacement passes repeated controls. By default, non-
supplicant processes pass through without RPC/SHM tracking; this process-role
isolation prevents unrelated client SHM identifiers from contaminating the
supplicant generation model.

## Current limitations

- One fault rule is accepted per process run.
- Referenced SHM bytes can be mutated when they use a supplicant-owned
  registered buffer. Whole-buffer content digests are not yet recorded.
- Non-meta synchronous supplicant mode gets a synthetic trace identity and
  cannot use `swap_pair`.
- The interposer records SHM registration/release generations but does not yet
  distinguish close from every possible lifetime transition in another
  process.
- Client cancellation tracing is disabled by default due to the documented
  observer effect in `docs/OBSERVER_EFFECTS.md`.
- FF-A semantic decoding currently understands the upstream stock SPMC test-SP
  action protocol. Other SP protocols retain raw direct-message events until a
  protocol adapter supplies end-to-end meaning.
- Concurrent FF-A direct messages do not yet provide a stable clean baseline
  with the current upstream user driver/test SPs, so the multi-SP stress
  workload is explicitly ineligible for automated campaigns.
