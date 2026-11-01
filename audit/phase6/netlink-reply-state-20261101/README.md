# Checked netlink reply decoding

The shared reply decoder rejects positive completion statuses and i32::MIN
with transport-level EPROTO. The request adapter then discards the uncertain
socket and returns ETIMEDOUT. Valid replies retain their exact kernel errno,
sequence filtering, interrupted-dump handling, draining and first-error
precedence. The socket loop still checks the kernel sender and absolute
deadline. Public APIs, dependencies and wire formats are unchanged.

`revision` identifies signed 99c5d8a. `extracted-pre-fix.patch` retains the
existing arithmetic after extraction and adds two malformed-status witnesses.
Both panic with unchecked negation in three GNU and three musl debug runs.
These are synthetic decoder inputs; this record shows neither a live kernel
emitting malformed status nor a daemon panic in release mode. source.patch
contains the correction and eight reply-state cases. Its final snapshot is
identical. The six per-run scenario/Incus scope files were added from those
parent snapshots after execution; their READMEs distinguish this provenance
from snapshots taken by the wrappers.

All eight cases pass three GNU and three musl repetitions. Ten native and
ten instrumented model/rule/service/startup repetitions, three musl model
runs, Rust 1.89, three additional musl architecture compile checks and common
gates pass. Eight isolated uninstrumented controls reject stale sequence
acceptance, missed interruption, overwritten errors, visiting after an
error, silent overrun, positive status acceptance, lost kernel errors and
lost visitor errors. The control source is restored; no control profiles
enter the collector.

GNU live collection passes 47 serial library, 24 Linux, five review, three
privileged binary, 29 process and 27 normal scenario cases. Three GNU/musl
host-adapter repetitions and namespace/warning guards pass. Instrumented
unprivileged Incus passes in 17.10 s; the real user manager and three thread-
limit runs pass. The unmodified musl root unit passes in 29.41 s.

Three shipped-musl normal suites pass in 162.81, 163.06 and 162.52 s. Their
paired unprivileged Incus cases pass in 18.46, 9.39 and 19.69 s. All probe
containers are deleted. Local live scope is Ubuntu 6.8.0-147-generic; these
results establish no broader distribution or live non-x86 qualification.

The fresh collector reports 8,456/8,687 lines (97.34%) and 1,687/1,852 branches
(91.09%), leaving 231 lines and 165 branches. There are no production
exclusions, profile mismatches or saturated regions. The earlier 99c5d8a
profiles are not merged. Production changes alter the denominators and
mapping catalog: 4,243 mappings stay identical, 56 change, 21 disappear and
12 are added. Every changed, removed or added mapping belongs to request.rs.
The record does not claim identical mappings or directly comparable totals.

The completed matrix frozen at fb0620d predates this production correction.
A new required matrix remains necessary. Complete clause/history/resource/
event-cost proof and 100% coverage remain open.
