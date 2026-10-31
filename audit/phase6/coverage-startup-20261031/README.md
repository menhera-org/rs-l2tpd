# Startup failures preserve caller ownership

Three isolated subprocesses deny actual startup syscalls: `clone`/`clone3`
return EAGAIN during runtime and service thread creation; `epoll_create1`
returns EMFILE during the service's Tokio engine construction. Each call
returns its precise I/O error and both adopted descriptors, preserving their
names and descriptor numbers. Sending bytes through each returned descriptor
proves that it remains usable. One inherited name is deliberately malformed.

A separate service test poisons the injected kernel's subscription initializer.
Its worker panic becomes an error and returns the adopted descriptor. A
library test checks non-I/O error diagnostics and their absent I/O sources.
Production implementation and API behavior are unchanged.

The final [common checks](ci-gates.log) pass, including stable GNU and musl
startup cases. All ten seeded fake runs pass: each executes 93 ordinary
library cases, one fake-conformance wrapper, 75 rule cases, 26 service cases
and one startup case that verifies all three faults. The live library cases
remain explicitly ignored in these native runs. Seed logs retain every result.

The first implementation placed the subprocess tests alongside concurrent
fake socket owners. A fork could briefly retain another test's tunnel-owner
descriptor before exec, making its immediate cleanup assertion fail. Moving
the subprocess cases into a separate Cargo test executable fixed that test
isolation defect. The original cleanup assertion remains unchanged.
[The failed checks](before-isolation-ci-gates.log) and
[original patch](before-isolation.patch) remain part of the record.

Merged coverage is **90.96% of production lines** (7,620/8,377) and
**78.16% of branches** (1,374/1,758), leaving **757 lines and 384 branches**.
There are no production exclusions. This adds 24 covered production lines
to the [fresh baseline](../coverage-production-20261031/README.md).
The 100% gate remains open.

The collection retains that baseline's live, manager and Incus profiles.
[The source check](production-source.log) confirms unchanged production
source, compiler, target and features. Changes to `src/error.rs` are entirely
inside its excluded test module. `revision` and `source.patch` identify the
new tests. [Native execution](native-coverage.log), [merged report](merged.log)
and [counts](counts.log) retain the result. No mismatched-profile warning
occurred. Cargo build durations are omitted.

With the baseline profile directory selected, run:

```sh
cargo +nightly llvm-cov --color never --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report --lib --test service --test startup
cargo +nightly llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```

`--no-report` already implies `--no-clean`. The initial command supplied
both; the CLI rejected it before running tests or changing profiles.
[That rejection](rejected-coverage-command.log) is retained separately.
