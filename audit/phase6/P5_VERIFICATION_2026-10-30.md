# Phase 6 P5: unprivileged system container — 2026-10-30

The maintainer approved the combined H11 contract: concurrent manager
activation may retain the kernel-random MAC after udev receives EBUSY;
the daemon must preserve that active interface. A separate ordered case
requires udev's persistent MAC before networkd activation and stable MAC
across clean re-creation with unchanged machine identity/name/policy.
These are distinct guarantees; the ordered case does not prove
unconditional persistent assignment with concurrent managers.

The actual command was `tests/docker/run.sh incus`, using all features
and `x86_64-unknown-linux-musl` executables. Each disposable
`images:ubuntu/24.04` container inherited no profiles/devices and had
`security.privileged=false`; no host network interface was attached.
Every run reported kernel `6.8.0-147-generic`.

| Final repetition | Buffer test | Incus scenario | Scenario duration | Record |
|---|---|---|---|---|
| 1 | 1 passed, FORCE=EPERM | 1 passed, 12 filtered out | 17.56 s | [record](incus-20261030T072810Z-3071995/) |
| 2 | 1 passed, FORCE=EPERM | 1 passed, 12 filtered out | 18.94 s | [record](incus-20261030T072838Z-3073503/) |
| 3 | 1 passed, FORCE=EPERM | 1 passed, 12 filtered out | 12.14 s | [record](incus-20261030T072907Z-3074855/) |

The production buffer test compares the subscription's receive buffer
with an explicit FORCE/ordinary-buffer probe. P5 additionally requires
the EPERM path to execute; all final runs observed 425984 bytes after
fallback. This is executed fallback evidence, not an inference from
being inside a user namespace.

The scenario installs the supplied unit through `--setup-systemd`,
checks bindv6only correction from 1 to 0, the PID file and exactly the
three required effective capabilities. It verifies networkd's
configured-name address, records the concurrent udev EBUSY outcome,
and checks index/MAC/address/UP preservation after reload, crash
adoption and requested re-exec. After SIGKILL it observes the process
gone and MainPID=0 while the manager's stored descriptor keeps the
same interface alive, then checks automatic restart/adoption. Ordered
clean re-creations get the same persistent MAC on different indices.
A staged session with configured MAC also gets its configured-name
networkd address. Explicit stops remove all tunnels/sessions and the
PID file.

No scenario was skipped. The final driver checks container deletion
and fails if cleanup fails. The three final cleanup commands succeeded;
a subsequent `incus list` found no probe container. Each record holds
kernel/configuration/build metadata, both test results, journals, manager
diagnostics and cleanup output.

The earlier failed Incus runs and fixture boot/reload corrections remain
in the accompanying audit directories. The global record explains why
the original unconditional persistent-MAC assertion changed with explicit
maintainer approval. No daemon workaround or forced interface lowering
was introduced.

[Final transcripts](entry/incus-final-1.log),
[second](entry/incus-final-2.log),
[third](entry/incus-final-3.log).

P5 passes locally. This does not prove P6's root QEMU mount sandbox:
Incus's systemd drop-ins affect the sandbox. The complete scenario suite,
required kernel matrix, merged 100% coverage, remaining rule citations
and strict CI integration are still open.
