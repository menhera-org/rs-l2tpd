# Adoption and failure recovery

The shared conformance suite now verifies IPv4 and IPv6 descriptor adoption
with asymmetric tunnel IDs, session records, four/eight-byte cookies and
the original device's lifetime identity. Closing the old descriptor leaves
the adopted tunnel and session intact; closing the adopted descriptor
removes both. A separate case checks foreign cookie lengths, configuration
admissibility and redacted formatting against a real session record.

All 17 shared cases pass on the fake and on live Ubuntu
`6.8.0-147-generic`. [Live execution](live.log) uses a disposable privileged
Docker container with `--network none` and a fresh namespace per case.
This focused run executes one conformance wrapper; the other 18 live kernel
cases and full scenarios were not repeated here. Other required kernels
still need the final matrix refresh with these additions.

The isolated startup executable additionally denies blocking-service thread
creation, engine construction and kernel socket opening. Together with the
three existing faults, all six return the precise I/O error and both inherited
descriptors with their original names/numbers and working byte transport.

Three policy cases verify removal retries under identifier/dump/name-deletion
failure, temporary rename/random-source failure during swaps, and an
incomplete adopted-session dump. They preserve the desired parent and device
identity, recover after retry, and issue no replacement creation. The staged
deletion test now injects the fake's actual `delete` operation; its former
`delete-name` key did not trigger a fault. New assertions check that no deletion
occurred before recovery.

[Common checks](ci-gates.log) and all ten seeded fake repetitions pass.
Each seed runs 93 ordinary library cases, one fake wrapper containing the
17 shared cases, 78 rules, 26 service cases and one startup case verifying
six faults. [Count checks](seed-counts.log) verify those results.

Two draft expectations failed before the final checks. The first expected an
unwanted parent to remain after a failed child deletion; S26 permits socket
closure to remove remaining children. The final removal test keeps the parent
desired and tests the child's retry. The adopted-socket draft expected
immediate shutdown completion, overlooking bounded asynchronous retirement;
the corrected test checks completion after the next fake-clock tick. These
development failures remain in [removal-draft.log](removal-draft.log) and
[removal-focused.log](removal-focused.log); production code is unchanged.

Merged production coverage is **91.83% of lines** (7,693/8,377) and
**78.56% of branches** (1,381/1,758), leaving **684 lines and 377 branches**.
There are no production exclusions. This adds 73 covered lines and seven
branches to the [startup record](../coverage-startup-20261031/README.md).
The 100% gate remains open.

Collection uses the same pinned nightly, all features, GNU target and profile
directory as the production baseline. [Production source](production-source.log)
is unchanged from `3f9d32a`, so its existing live, manager and Incus profiles
remain applicable. `revision` and `source.patch` identify the final tests;
`initial-source.patch` identifies the earlier focused live collection.
[Native collection](native.log), [rule collection](rules-coverage.log) and
[final report](final-merged.log) retain the commands' output. Cargo build
durations are omitted. No profile-mismatch warning occurred.

```sh
cargo +nightly llvm-cov --color never --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report --test kernel-fake --test kernel-linux --test startup
# Run the generated kernel-linux executable in the isolated live container:
# --ignored --exact conformance_on_the_linux_kernel --nocapture
cargo +nightly llvm-cov --color never --locked --all-features --target x86_64-unknown-linux-gnu --branch --no-report --test rules
cargo +nightly llvm-cov report --target x86_64-unknown-linux-gnu --branch --show-missing-lines
```
