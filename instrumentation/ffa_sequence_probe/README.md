# Generic FF-A sequence probe

This probe executes a data-driven sequence against the public
`arm_ffa_user` ABI. It exists to turn TEEWeaver's semantic proposals into
runtime histories without compiling a one-off program for each suspected bug.
It does not contain an advisory name, source location, expected vulnerable
sequence, or target-side patch.

The plan language is line-oriented:

```text
endpoint A 11111111-2222-3333-4444-555555555555
endpoint B aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
ping A
ping B
share h A 4096
send A 5 h
send B 5 h
send A 6 h
reclaim h
sleep 1000
```

Commands:

- `endpoint NAME UUID`: resolve an existing Secure Partition;
- `ping ENDPOINT`: send action 0;
- `share HANDLE ENDPOINT [SIZE]`: create a live FF-A memory handle;
- `send ENDPOINT ACTION [HANDLE]`: send an arbitrary observed test action;
- `reclaim HANDLE`: reclaim a Normal-World-owned handle;
- `sleep MICROSECONDS`: move the next transition across a schedule boundary.

Each executed step emits one JSON record to stdout with the ioctl result,
errno, response, endpoint, and handle where applicable. Runtime rejection does
not stop later steps; this is necessary to observe failure atomicity and
post-failure liveness. Syntax, endpoint-resolution, and unknown-handle errors
remain fatal. Run it under the existing interposer to obtain the full merged
TEEWeaver trace.

Build with:

```sh
make -C instrumentation/ffa_sequence_probe \
  OPTEE_ROOT=/path/to/optee-qemu
```
