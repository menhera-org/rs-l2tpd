# Runtime and socket error boundaries

Four test-only additions qualify existing error handling. Production code is
unchanged from `revision`; `source.patch` and `final-source.patch` agree.

- Closing a reload receiver returns its queue error without advancing the
  generation, accepting a request or consuming admission capacity.
- Either subscription initializer may fail. The original inherited names
  and descriptors must be returned, still usable; failure of the second
  initializer must also release the first reader. The existing test host
  gains a two-stage failure hook and checks reader ownership by reference
  count.
- An accepted reload whose worker cannot spawn returns EAGAIN, closes the
  service queue and never invokes its callback. The existing seccomp helper
  applies the fault to already-running worker threads through TSYNC.
- Socket adaptation preserves raw EIO/ENOTCONN values, maps the typed family
  refusal to EAFNOSUPPORT and other controlled library refusals to EINVAL.
  Six synthetic inputs require four non-OS diagnostics. They are not live
  observations of invalid kernel replies or wrong daemon operation order.

Ten native and instrumented model/rule/service/startup repetitions, three
musl model runs, common gates, Rust 1.89 and ARM64/RISC-V64/PowerPC64LE musl
compile checks pass. Three GNU/musl socket repetitions pass. Three serial
instrumented runs cover the socket case, reload-spawn failure and all four
startup cases. The full GNU live suite passes: 50 serial library, 24 Linux,
five review, three privileged binary, 29 process and 27 normal scenario
cases. Local live scope is Ubuntu 6.8.0-147-generic; cross-architecture
results are compile checks only.

Nine independent uninstrumented controls each fail the intended assertion:
advancing a rejected generation, discarding inputs, leaking a partial
reader, omitting TSYNC, losing the spawn error, losing raw errno,
misclassifying a family refusal, misclassifying a library refusal, and
muting its diagnostic. Control patches and logs identify each change.

The report reaches **8,482/8,687 lines (97.64%) and 1,696/1,852 branches
(91.58%)**, leaving 205 lines and 156 branches. Socket handling covers
103/103 lines and 12/12 branches; request handling remains complete.
All prior 4,319 mappings are unchanged; test callers add eight service
instantiations. No production exclusion, profile mismatch or saturated
region is present. The collector continues the unchanged checked-reply
implementation; profiles from earlier production implementations are not
merged.

`dependency-source.log` identifies the pinned l2tp 0.5.0 error definitions
and existing fault helper. This package adds no dependency or production
API. Required-matrix, manager and system-container scopes remain those of
their separate records. The global coverage and complete clause-proof gates
remain open.
