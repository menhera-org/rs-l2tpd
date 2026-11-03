# Creation-capture ordering, November 3

This record starts from signed `f771c24`. The final production change is
not yet signed, and its required-kernel matrix and production coverage have
not run. Earlier results do not qualify the changed production source.

The final clause audit found a gap in S8. The lifetime subscriber armed a
temporary name before session creation and accepted the first registration
under that name. A second writer could create that name, let the subscriber
capture it, rename it away, and then let the requested L2TP session register
under the released name. The original isolated witness produced:

```text
CREATION_RACE foreign_index=4 actual_session_index=5 captured_index=4 proof=Proved
assertion failed: foreign name history authorized the wrong device
```

The fix sends an ordered route-netlink lookup after the L2TP creation
request. Its reply closes the capture window after earlier notifications.
The capture accepts one distinct registration, rejects two as uncertain,
and never uses the lookup to obtain an index. A missing registration still
waits until the original creation deadline. S8 and the kernel evidence pages
now state this rule and its recovery limit.

The fixed musl library executable passes all 31 ignored live unit cases, and
the Linux integration executable passes all 24 live cases in one disposable,
networkless privileged container. The forced interleaving passes ten
separate processes. Each observes different foreign and session indices and
returns `ETIMEDOUT` instead of a registration. The pre-existing
timed-creation case still waits five seconds and releases the capture name.

The first common-gate run failed because the new live test lacked the
source-link comment required for every function in `kernel::linux`. After
adding the K20/K29 citation, the complete `./test-ci-gates.sh` pass is
green. Coverage collection, the required-kernel matrix, Incus and root-unit
qualification remain pending.

Signed `f771c24` has a failed
[CI run 41595151274](https://github.com/menhera-org/rs-l2tpd/actions/runs/41595151274).
Its live and production-coverage jobs pass, while the build job fails before
badge coverage because ANSI color bytes entered the source-work executable
path parsed from Cargo output. The working change passes `--color never`
to that machine-readable command. This correction has not yet run in CI.

