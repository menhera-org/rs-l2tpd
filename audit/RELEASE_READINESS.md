# Release readiness

Binary distribution is held for the two packaging fixes below.
Production code and tests match qualified source `81d49f9`; release tooling
is `97fbbf8`. The [verification record](VERIFICATION.md) gives the completed
gates, exact scope and signed evidence.

| Priority | Finding | Required change |
|---|---|---|
| Must fix | [postinst](../musl-deb/postinst) starts the service without consulting `policy-rc.d`. A Debian container reproduction with policy exit 101 still records `systemctl enable --now`. | Use Debian's policy-aware service helpers and test denied startup. |
| Must fix | [Debian packages](../musl-deb/src/main.rs) omit third-party notices; [tarballs](../build-release.sh) contain only the executable. Tokio's MIT notice is one verified omission. | Ship the project licenses and required notices for linked dependencies/runtime libraries in both formats; check artifact contents. |
| Should fix | Installed README/installation links point to operator/developer files absent from the package. Checkout link checks cannot detect this. | Ship the referenced documentation or use package-specific links to the published book; check the installed tree. |
| Should fix | The pinned cross 0.2.5 bootstrap has one reported vulnerability and six warnings, including yanked dunce; the three project lockfiles pass. The verified Unix path delegates to modern Rust's standard library, and atty's unsoundness is Windows-specific. | Refresh the upstream tool lock or pin a maintained audited revision, then repeat reproducibility checks. Retain the nonzero audit result without an ignore rule. |
| Should fix | The root-unit gate requires a prepared nd-test:u2404 image; its documented recipe exists only in audit history and installs packages through networked Docker RUN steps. | Maintain that active recipe outside audit/ with offline package preparation, then qualify the rebuilt image. |

The [tool advisory](https://rustsec.org/advisories/RUSTSEC-2023-0018.html) and
[verified source](https://docs.rs/crate/remove_dir_all/0.5.3/source/src/lib.rs)
are distinct from daemon dependency findings.

The operator guide's musl resolver wording has been corrected. It now
distinguishes the linked libc from the host's glibc NSS configuration;
the normative V3 contract is unchanged. See [peer discovery](../docs/peer-discovery.md#resolver-choices).

Debian documents its policy-aware maintainer-script interface in
[deb-systemd-invoke(1p)](https://manpages.debian.org/trixie/init-system-helpers/deb-systemd-invoke.1p.en.html).
[Tokio's license](https://raw.githubusercontent.com/tokio-rs/tokio/tokio-1.54.1/LICENSE)
contains the notice requirement used in the artifact review.

The review traced configuration loading/reload, scheduling, resolver
admission, netlink input checks, lifetime proofs, session ownership,
descriptor handover, restart/shutdown, packaging and documentation.
The load assumption was 300 configured bindings with unrelated host
activity, failures, reloads and namespace/interface reuse.

No further daemon regression was verified in those paths. Arm64 runtime
execution and full Debian/Rocky service-manager/SELinux integration remain
outside qualification. Upstream implementations and every test fixture
were not independently re-audited.
