# Portable verification records

CONTRIBUTING.md's scope rule excludes machine-specific facts from the
repository. Phase 6 records retain the kernel targets, commands, feature
selection, test counts, measured test behavior and cleanup outcomes.

Incus captures now omit volatile host allocation fields and replace the
host storage-pool name with an explicit omission marker. The driver
records the portable pool-selection command instead of its host-specific
expansion. The remaining configuration proves security.privileged=false,
no inherited profiles, a root disk and no NIC. The live Rust assertion
independently requires the container's UID mapping to be unprivileged,
without printing the host range.

Cargo's elapsed build durations are removed; test durations and asserted
convergence bounds remain verification evidence. Verification tool pins
belong in docs/dependencies.md; machine installation transcripts are
removed. Previous test outcomes, failed assertions, kernel versions and
cleanup evidence are retained.
