# Binary verification

Ordinary CLI, file, rendering, PID, signal-coalescing, store and installer
cases run without privilege:

```sh
cargo test --locked --all-features --target x86_64-unknown-linux-musl --bin rs-l2tpd --test process
```

The binary's unit tests live beside their modules. `tests/process.rs`
executes the actual binary; its ignored cases use a real Linux kernel.
Each process has a bounded event wait and a cleanup guard. Each kernel case
unshares a network namespace; no host network configuration is changed.
Run these tests serially.

Build once with the command above and set `BINARY_UNIT` and `PROCESS_TEST`
to the absolute test executable paths Cargo prints. The process test's
embedded binary path must exist inside the container, so mount the checkout
read-only at its original absolute path:

```sh
repo=$(pwd)
docker run --rm --network none --privileged \
  --mount "type=bind,source=$repo,target=$repo,readonly" \
  --mount "type=bind,source=$BINARY_UNIT,target=/binary-unit,readonly" \
  --mount "type=bind,source=$PROCESS_TEST,target=/process-test,readonly" \
  --entrypoint sh rs-l2tpd-audit-vm:local -ec '
    uname -r
    /binary-unit --ignored --exact pidfile::permission_tests::precreated_permissions_links_and_owner --nocapture
    /binary-unit --ignored --exact pidfile::removal_tests::removal_uses_inode_after_directory_owner_changes --nocapture
    /binary-unit --ignored --exact files::filesystem_tests::permission_errors_name_unreadable_unlistable_and_uninspectable_paths --nocapture
    /process-test --ignored --test-threads=1 --nocapture
  '
```

The image is built by the [kernel instructions](../kernel/README.md).
Two permission fixtures drop a child to uid/gid 65534; the third changes
a PID directory's ownership after publication. The process cases
need writable namespace-local network sysctls for the tunable handshake.
The overlapping-instance case takes the real ten-second conflict budget.
Do not run these privileged cases directly on the host.

For glibc, rebuild with `--target x86_64-unknown-linux-gnu` and use
`rs-l2tpd-coverage:phase6`, built by
`docker build --network none -f tools/coverage/Dockerfile -t rs-l2tpd-coverage:phase6 .`.
That image supplies the GNU runtime and existing fixture tools. Images
select userspace, not another kernel. A separate run
of `foreground_reload_and_clean_shutdown_without_network`, after
`mount -t tmpfs tmpfs /proc` inside the privileged container, checks the
process with procfs absent and tunable fixing disabled. Run
`setup_prefix_preserves_configuration` there as well to check the installer's
procfs-free executable lookup; it is an ordinary test, so run it without
`--ignored`. Docker/runc refuses
covering /proc directly through its outer mount options.

The ignored `installer_enables_once_and_never_restarts` case installs only
inside this disposable container and records systemctl calls through a
fixture executable; it never contacts a manager or changes the host.

The real-manager test requires a user systemd manager. It uses the native
binary transport, verifies the template's address-family property and
checks `NFileDescriptorStore` before and after barrier-confirmed withdrawal:

```sh
systemd-run --user --no-pager --wait --pipe --collect \
  --unit=rs-l2tpd-phase5-notify \
  --property=Type=notify --property=NotifyAccess=all \
  --property=FileDescriptorStoreMax=8 --property=NoNewPrivileges=yes \
  '--property=RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6' \
  --property=TimeoutStartSec=10s --property=RuntimeMaxSec=20s \
  --setenv=PHASE5_NOTIFY_UNIT=rs-l2tpd-phase5-notify.service \
  "$BINARY_UNIT" --ignored --exact \
  fdstore::manager_tests::actual_manager_processing_and_address_family_filter --nocapture
```

This user-manager case tests the address-family restriction and descriptor
protocol. The complete root system-unit mount sandbox is qualified separately:

```sh
tests/kernel/run-guest.sh "$KERNEL_IMAGE" "$KERNEL_MODULES" "$KERNEL_CONFIG" systemd "$RECORD"
```

Provide the prepared Ubuntu root image described in
[kernel verification](../kernel/README.md#maintained-runners). The unmodified
unit passes its tunable-write exception, dedicated PID path, capability set,
crash/store adoption, re-exec and clean shutdown on Ubuntu 24.04 with kernel
6.8.0-147. Three fresh unprivileged Incus runs pass too. These do not qualify
other distributions' managers. The template is also parsed by tests and
checked with `systemd-analyze --no-pager verify`.

The recorded required normal guests each pass all 37 process cases and 27
scenarios. All optional Debian 13 and Rocky 9/10 guests pass their normal
and clock profiles on fixture fix `69a0b42`: 37 process cases and 28 scenarios
per normal guest. The added scenario tests nlmon capture startup; the daemon
and existing assertions are unchanged.
Debian 12 receives best-effort degradation outside the support target.
GNU coverage, stable musl, CI and exact source/host scope are indexed by the
[current verification record](../../audit/VERIFICATION.md). Historical
executions remain in Git history.
