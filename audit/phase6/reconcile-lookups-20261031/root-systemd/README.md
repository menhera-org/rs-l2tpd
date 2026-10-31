# Supplied root system unit

The unmodified all-feature musl binary passes the complete root-systemd
scenario on Ubuntu `6.8.0-147-generic` in 26.73 seconds. No drop-ins change the
shipped unit. `run.log` retains exact capabilities, mount/tunable restrictions,
FD-store barriers, daemon restart, ordered MAC checks and final cleanup;
`ROOT_SYSTEMD_RESULT=0` records success. `command.log` identifies QEMU options,
`build.log` the executables and `artifacts.log` their hashes.

This is the identifier-index proposal from the parent record, not the final
five-target matrix. The concurrent MAC write receives EBUSY; both ordered
creations receive the same persistent address, within the approved H11 limits.
