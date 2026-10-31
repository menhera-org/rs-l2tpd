# Supplied root system unit

The unmodified all-feature musl binary passes the complete root-systemd
scenario on Ubuntu `6.8.0-147-generic` in 27.10 seconds. No drop-ins alter the
shipped unit. `run.log` retains exact capabilities, mount/tunable restrictions,
FD-store barriers, restart, ordered MAC checks and cleanup;
`ROOT_SYSTEMD_RESULT=0` records success. The concurrent creation gets a
persistent MAC address; both ordered creations get the same persistent address.

The parent record identifies the rename/recreation proposal. This scoped
sandbox run does not stand for the final required-kernel matrix.
