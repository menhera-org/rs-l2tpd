# Coverage input validation follow-up

Continuation of signed `db7c1d2`; qualified by the subsequent batch's
full common checks.

The checker now includes its mapped source-line inventory in the snapshot,
rejects missing counted line maps and requires every reported covered line
to have an executed function region. Inventory format 2 rejects the older
snapshot format. Source hashes disable Git clean filters: a configured filter
must not hide a changed source file.

Ten tests pass on GNU and musl, as do warning-denied Clippy, Rust 1.89 checks
and compiler-generated calibration. Four independently restored controls
fail their intended assertions: allowing empty counted line maps, accepting
invented line executions, omitting the mapped-line inventory and applying
a Git clean filter while fingerprinting. `commands-controls.txt` retains
the three line-map controls; `control-git-filters.log` retains the fourth.

The existing production export still reports **8,441/8,441 merged lines and
1,834/1,840 outcomes**, and the checker exits **1**. The older inventory
exits **2**, rather than passing with fewer checks. The raw export is
unchanged. These input checks do not establish a new before-build snapshot
for that earlier collection or pass the production 100% gate.
