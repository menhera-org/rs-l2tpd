# rs-l2tpd documentation

[![crates.io](https://img.shields.io/crates/v/rs-l2tpd.svg)](https://crates.io/crates/rs-l2tpd)

rs-l2tpd provides Linux kernel L2TPv3 Ethernet pseudowires and a Rust library
for managing them. The source, the issue tracker and the audit reports are
in the [GitHub repository](https://github.com/menhera-org/rs-l2tpd).

| Guide | Contents |
|---|---|
| [Installation](installation.md) | Building, kernel requirements, capabilities, procfs, systemd and other init systems |
| [Configuration](configuration.md) | TOML example, files and merging, resolvers, validation and degraded operation |
| [Sessions](sessions.md) | Interface identity, child namespaces, MAC preparation and session cookies |
| [Operation](operation.md) | Readiness, disconnected tunnels, source selection, bindv6only, reload, restart and shutdown |
| [Library](library.md) | Features, asynchronous and blocking services, control handles |
| [Testing](testing.md) | Compatibility expectations, validation suites, kernel test pitfalls |
| [Contracts](contracts.md) | The rules every change must keep, and the tests that guard them |
| [Specification](spec/README.md) | Requirements, promises, architecture and the normative behaviour in every condition, with the known gaps of the implementation |

The guides describe the behaviour the specification defines. Where the
current release still differs, the specification's
[known gaps](spec/README.md#known-gaps) list it.

These pages use relative Markdown links, so navigation works in a checkout
and on GitHub. The directory can also be used as the `/docs` source for
GitHub Pages: `_config.yml` enables the supported README-index and relative-link
plugins. They make this README the site index and translate links to rendered
pages, including project-site prefixes. See
[GitHub's Jekyll documentation](https://docs.github.com/en/pages/setting-up-a-github-pages-site-with-jekyll/about-github-pages-and-jekyll).
