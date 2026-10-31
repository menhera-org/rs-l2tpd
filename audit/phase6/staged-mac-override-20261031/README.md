# Staged configured MAC: H11 decision pending

**P5 remains unresolved.** An unmodified musl Incus run fails after 31.93
seconds at `staged configured MAC and networkd address`. Direct/concurrent
and both ordered persistent-MAC cases pass first. The retained interface is
UP with networkd address `198.18.0.1/24`, but MAC `ea:90:45:d1:31:c8` instead
of configured `02:00:5e:00:53:01`. No assertion or specification is changed
to count this as a pass. The container is deleted.

The failing record is `../incus-20261031T201422Z-328683/`; its controller is
in `../coverage-simplify-20261031/incus-musl-controller.log`. That proposal's
source is recorded by the parent coverage package. Later instrumented and
root profiles pass individually; they do not erase this failure or establish
P5 determinism.

## Baseline reproduction

The preceding committed daemon, `de8ac734068f144d5a2d2519fbda7ebaf2303fee`,
also exhibits the override. `baseline-witness.sh` runs the all-feature musl
binary in a disposable unprivileged Ubuntu container without a NIC. The kernel
is `6.8.0-147-generic`; systemd is `255.4-1ubuntu8.18`. Udev debug logging is
enabled. Creation three produces persistent MAC `1e:9f:56:5c:05:8b` instead
of the configured value; creations one and two retain the configured value.

`baseline-journal.log` records the worker reading assignment type 1, using
creation name `rsl2tp-t480519` as stable input and applying that exact persistent
address. The daemon publishes `incusl2tp`; the final link remains UP and
addressed. This rules out the current simplification batch as the origin.
Publication requires successful configured-address application in the daemon;
the observed final value matches udev's assignment. The exact ordering of all
netlink requests is not traced.

`baseline-controller.log`, `baseline-final-link.log`, `baseline-binary.sha256`
and `baseline-source-check.log` retain the observations and source checks.
The archive adds only a `#[cfg(test)]` store-cost module, absent from the normal
binary build. No shipping baseline source is changed. The first diagnostic
loop hits the supplied unit's start limit after five creations; its logs are
separate. The final diagnostic adds only a `StartLimitIntervalSec=0` drop-in
to permit repeated starts. This is a diagnostic control, not unmodified P6.
Both containers are deleted.

## Source and conflicting assumptions

H11 currently says the configured address takes precedence over udev's
persistent policy. S12/G4 require preserving a manager's later MAC override.
The initial application and a later policy assignment need distinct contracts.

In upstream systemd v255
[link configuration](https://github.com/systemd/systemd/blob/v255/src/udev/net/link-config.c),
`link_new` snapshots `addr_assign_type`; `link_generate_new_hw_addr` later
uses the saved value and chooses a policy address. `link_apply_rtnl_settings`
then sends the change. The decision and assignment are separate operations.
`systemd-source.sha256` identifies the inspected upstream file; installed
Ubuntu patches are not claimed to be byte-identical to that tag.

## Prepared correction

`proposed.patch` is **not applied**. It explains the stale-decision race and
retains S12/G4's manager-override rule. It gives the configured-MAC test one
explicit authority, using `MACAddressPolicy=none` in a `.link` file that matches
both the temporary creation name and configured name. The concurrent and
twice-ordered persistent-policy cases stay unchanged.

`authority-control.sh` validates that proposed policy with the baseline daemon:
three successive staged creations retain `02:00:5e:00:53:01`, select the explicit
`.link` file and receive the networkd address. `authority-control/controller.log`
and its journal retain `AUTHORITY_PRESERVED=3`. Its container is deleted.
This validates the proposed policy mechanism, not the unapproved H11 gate.

Phase 6 forbids changing the precedence promise or relaxing its acceptance
condition without the maintainer's decision. The question is deferred until
the requested 16:00–23:00 UTC quiet window ends. Independent packages continue.
Common checks pass in `common.log`; no P5 pass is claimed.
