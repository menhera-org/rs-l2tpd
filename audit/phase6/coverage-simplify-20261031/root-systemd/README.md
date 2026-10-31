# Supplied root system unit

The unmodified all-feature musl binary passes the complete root-systemd case
on Ubuntu `6.8.0-147-generic` in 28.90 seconds, without drop-ins. The parent
record identifies source and features. Only coverage-only exec flush calls
were subsequently removed; they were compiled out of this musl binary.

`run.log` retains the exact capability and mount assertions, descriptor-store
barriers, restart and cleanup. `ROOT_SYSTEMD_RESULT=0` records success. The
concurrent creation gets a persistent MAC and the ordered checks pass.
This individual run does not resolve the staged-MAC nondeterminism retained
in the separate H11 record and does not stand for the required-kernel matrix.
