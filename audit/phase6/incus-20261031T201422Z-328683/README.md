# Failed unmodified musl Incus case

`tests/docker/run.sh incus` fails on Ubuntu `6.8.0-147-generic` after
31.93 seconds. Direct/concurrent and twice-ordered persistent-policy checks
pass, but the staged configured-MAC check times out. The interface remains
UP and networkd-addressed with another MAC. The container is deleted.

The H11 investigation and unapplied proposal are in
`../staged-mac-override-20261031/`. This run is failed, including when later
instrumented or root profiles pass individually. The parent coverage record
retains the controller and source proposal.
