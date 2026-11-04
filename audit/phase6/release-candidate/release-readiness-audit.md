# Release readiness audit

Production source: 81d49f9d2e54e89c47aefa7ae9edc4943e6374f8.
Release tooling: 97fbbf8e4b2d650e9517a41d0cf05363189c531f.
All 13 required profiles, six optional profiles and the unmodified root unit pass.

What this repo does: rs-l2tpd reconciles Linux L2TPv3 tunnels and Ethernet
sessions and exposes the same controller as a Rust library. This audit assumes
up to 300 configured bindings, unrelated host network activity, reloads,
interface/namespace reuse and service restarts.

## Must fix

1. **Package service actions bypass administrator policy** (musl-deb/postinst:7).

   What this is: First installation reloads systemd and enables/starts the service.
   Problem: The script calls systemctl directly. A disposable Debian 13
   reproduction supplies policy-rc.d returning 101; postinst never consults
   that policy and still requests enable --now. An administrator can therefore
   get service startup, and configured network changes, despite denying starts.
   Fix: Use Debian's service-management helpers for maintainer-script actions,
   preserve administrator enable/mask policy, and add a policy-denial consumer case.
   If we skip it: Installing a package can start networking against local policy.

   Evidence: package-policy-repro.log.
   Debian documents the policy-aware helper in
   [deb-systemd-invoke(1p)](https://manpages.debian.org/trixie/init-system-helpers/deb-systemd-invoke.1p.en.html).

2. **Binary artifacts omit required license notices** (musl-deb/src/main.rs:107;
   build-release.sh:65).

   What this is: Release archives ship statically linked executables.
   Problem: The tarball writer includes only rs-l2tpd. The Debian package adds
   this project's Apache/MPL texts but no third-party notices. Tokio is one
   concrete MIT-only linked dependency whose copyright and permission notice
   are absent from both artifact formats.
   Fix: Ship project licenses and the notices for linked Rust dependencies and
   bundled runtime libraries with both formats, and verify them in artifact tests.
   If we skip it: The binary release lacks notices its dependencies require.

   Evidence: package listings, Cargo's normal dependency graph and
   [Tokio's license](https://raw.githubusercontent.com/tokio-rs/tokio/tokio-1.54.1/LICENSE).

## Should fix

3. **Installed documentation points to files absent from the package**
   (musl-deb/src/main.rs:107; docs/installation.md:4).

   What this is: The package installs the repository README and a flattened installation.md.
   Problem: Their relative links target docs/operation.md, kernel-support.md,
   developer.md and other files that are not installed. Repository/mdBook link
   checks pass because those files exist in the checkout.
   Fix: Ship documentation at its referenced paths or provide package-specific
   links to the published book; check links against the installed package tree.
   If we skip it: Administrators following local package documentation hit missing files.

4. **The pinned build tool retains a failing dependency audit** (release-config.sh:4).

   What this is: Release CI installs cross 0.2.5 with its published lockfile.
   Problem: That lockfile returns audit exit 1 for remove_dir_all 0.5.3 and
   reports six warnings, including yanked dunce 1.0.2. The project lockfiles
   are clean. The verified Unix implementation re-exports modern Rust's
   standard-library deletion; atty's unsoundness is Windows-specific, so
   this scan does not demonstrate a Linux daemon vulnerability.
   Fix: Pin a maintained, audited cross revision or refresh the lockfile
   upstream, then repeat artifact comparisons. Keep the published result visible.
   If we skip it: The reproducible tool bootstrap continues to carry a failing
   audit and yanked/unmaintained inputs.

   Evidence: dependency-audit/cross.log and dependency-audit/applicability.md.
   Sources: [crate source](https://docs.rs/crate/remove_dir_all/0.5.3/source/src/lib.rs),
   [RustSec](https://rustsec.org/advisories/RUSTSEC-2023-0018.html),
   [Windows-only atty warning](https://rustsec.org/advisories/RUSTSEC-2021-0145.html).

5. **The root-unit image bootstrap is outside the maintained gate tree**
   (tests/kernel/run-guest.sh:17; docs/developer.md:124).

   What this is: The root-systemd profile consumes a prepared nd-test:u2404 image.
   Problem: Its only documented recipe is under audit/ in a past commit.
   That recipe performs apt-get update/install inside Docker. A fresh checkout
   cannot use that bootstrap with the required networkless Docker build flow.
   The completed unit run qualifies the supplied image, not that bootstrap.
   Fix: Maintain the active image recipe outside audit/ and provide an offline
   package preparation/build path, then qualify a freshly rebuilt image.
   If we skip it: Maintainers need historical files and a conflicting build
   procedure to recreate a current acceptance-test input.

   Evidence: the current runner/image prerequisite and
   [the archived recipe](https://github.com/menhera-org/rs-l2tpd/blob/c599b1f9c2343a3ffe6be315a6d77c4b68106744/audit/phase5-completion/networkd/Dockerfile).

The operator guide's musl resolver wording was corrected during the
authorized documentation refresh. It now distinguishes the linked libc
from the host's NSS configuration; normative V3 is unchanged.

## Scope

Reviewed startup/readiness, bounded configuration reads and reloads,
PID-file authority and restart handover, descriptor-store protocol,
service scheduling and resolver admission, netlink framing/sender checks,
lifetime proofs, session identity/recovery, package writers/ELF validation,
maintainer scripts, build/deployment workflows and operator/developer chapters.
The existing tests and conformance records supply execution evidence; source
reading alone is not counted as a test. Rust 1.89 native and musl checks pass.

Verdict: Hold binary distribution for findings 1 and 2. No additional daemon
regression was verified in the reviewed paths.

Not checked: Every test fixture or every upstream implementation was not
independently re-audited. Arm64 runtime execution and complete Debian/Rocky
service-manager/SELinux integration are outside the current qualification.
The daemon, coverage-tool and package-builder lockfiles pass cargo audit with a fresh official registry index. cross's published lockfile remains non-clean as finding 4 records.
