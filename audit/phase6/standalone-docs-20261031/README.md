# Standalone documentation check, 2026-10-31

P7 requires the `docs/` tree to stand alone. At revision
`069b31b741831c5100c81a50f33e5f53fbd20de8`, 36 Markdown links left that tree.
The four affected pages now name repository files in prose or code. Links
between documentation pages remain clickable. Kernel results and coverage
requirements are unchanged.

`check.rs` checks inline local file links, rejects paths outside `docs/`,
requires internal targets to exist, and rejects symlinks that escape the tree.
It checks file targets, not fragment identifiers or external URLs. The tree
contains no local reference-style link definitions.

Commands:

```sh
rustc audit/phase6/standalone-docs-20261031/check.rs -o /tmp/check-docs
/tmp/check-docs /tmp/phase6-docs-before
/tmp/check-docs /tmp/phase6-docs-alone
/tmp/check-docs "$PWD"
./test-ci-gates.sh
```

The first directory contains only `docs/` from the recorded base revision;
the second contains only the corrected `docs/`, copied with `cp -R docs`.
The baseline fails with 36 outside links (`before.log`). Both corrected copies
pass: 27 Markdown files, 813 local file links, zero outside links
(`docs-only.log` and `checkout.log`). The common checks are in `common.log`.

This proves the local file-link part of P7. The final clause inventory,
production coverage and current-source kernel matrix remain separate gates.
