# Mainline changed to 7.4-rc1 before the requested pause

The pre-pause publication check found mainline **7.4-rc1**, replacing the
7.3 target of the completed thirteen-profile matrix. The Ubuntu and vanilla
selections remain 6.8.0-147.147, 6.8.12, 7.0.0-42.42 and 7.0.14.
The new target is **not built or boot-tested**. P3 is open again.

The old parser rejects the actual published RC document; the witness is
retained in `legacy-control.log`. The corrected parser accepts final and
RC tags, rejects malformed candidates and derives `7.4.0-rc1` as the guest
release. The builder validates the same tag forms and chooses the published
git.kernel.org gzip archive for RCs, retaining CDN xz archives for final
releases. Its mounted source path is independent of compression.

Parser, release-name, URL-selection, argument-validation, POSIX syntax and
ShellCheck tests pass. The real RC archive was fetched from the publication
document's source URL. Its gzip header and Makefile VERSION/PATCHLEVEL/
EXTRAVERSION match 7.4-rc1; the source git-blob digest is recorded.
This verifies archive selection and extraction, not a completed kernel build.

The actual publication documents and current selection are retained in
`../pause-20261101/publication-current/`. The original failing resolution
is also retained. Source patches identify the tooling change. Production
Rust code and the specification are unchanged.

Resume by building the RC in the networkless builder, reviewing its kernel
source evidence, then running normal, clock and both IPv6-absent profiles.
Re-resolve the complete required set before and after qualification.
The preceding 7.3 results remain historical evidence and do not qualify
7.4-rc1. P4 and complete clause proof also remain open.
