# Dependency audit scope

The daemon, coverage tool and package-builder lockfiles pass with a fresh
crates.io index and no ignored advisories. The first attempt's incomplete
index lookup is retained in initial-registry.log; it is not the final result.

cross 0.2.5's published lockfile returns 1: remove_dir_all 0.5.3
(RUSTSEC-2023-0018), four unmaintained packages, the Windows atty
unsoundness warning and yanked dunce 1.0.2. These are build-tool inputs,
not daemon dependencies. No result has been suppressed or reclassified by
a cargo-audit ignore rule.

The checksum-verified remove_dir_all 0.5.3 source re-exports
std::fs::remove_dir_all under cfg(not(windows)); its custom implementation
is cfg(windows). tempfile 3.3.0 imports that wrapper. The canonical Linux
build uses modern Rust; Rust's standard-library race was mitigated in
1.58.1. We therefore do not identify a reachable Linux implementation of
the reported crate race in this build path. atty's cited unsoundness is
Windows-specific. Keep the toolchain maintenance finding open rather than
calling its audit clean.

Sources:
- https://docs.rs/crate/remove_dir_all/0.5.3/source/src/lib.rs
- https://rustsec.org/advisories/RUSTSEC-2023-0018.html
- https://rustsec.org/advisories/RUSTSEC-2021-0145.html
- https://blog.rust-lang.org/2022/01/20/cve-2022-21658/

Verified published source checksums:
- remove_dir_all 0.5.3: 3acd125665422973a33ac9d3dd2df85edad0f4ae9b00dafb1a05e43a9f5ef8e7
- tempfile 3.3.0: 5cdb1ef4eaeeaddc8fbd371e5017057064af0911902ef36b39801f67cc6d79e4
