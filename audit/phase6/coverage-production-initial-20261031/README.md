# Initial production-scope collection, superseded

These native, live, user-manager and Incus runs passed. The first live
launcher attempted to execute the non-executable audit helper directly and
ran no tests; `live-launch.log` records that failure. Invoking the documented
`sh` command then passed all 26 scenarios in 157.21 seconds. Incus passed
its full case and exported seven daemon profiles.

Review then found two feature-gated signal test modules and a test-only
report helper that still needed coverage attributes. This collection is
therefore superseded by the separate fresh
[complete production-scope baseline](../coverage-production-20261031/README.md).
Its profiles are not merged into that report. The retained source patch
identifies this earlier instrumentation scope; no 100% gate result is
claimed here.
