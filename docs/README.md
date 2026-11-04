# rs-l2tpd

rs-l2tpd maintains Linux L2TPv3 tunnels and Ethernet pseudowires. It keeps
working while links, routes, addresses and DNS become available, and
preserves tunnel identities across configuration reloads.

Start with [installation](installation.md), then [configuration and operation](operation.md).
The [kernel support guide](kernel-support.md) describes qualified targets,
container requirements and degradation on older hosts.
[Peer discovery](peer-discovery.md) explains resolver choices.

Version 0.2.0 is prepared for release; it has not been published.
[Verification scope](developer.md#kernel-evidence) distinguishes tested behavior
from source and upstream evidence. Repository file `audit/VERIFICATION.md`
identifies the source and qualification results.

[Development and verification](developer.md) covers the library, contribution checks and
test execution. The [specification](spec/README.md) defines the behavioral
contract.

These pages are published as an [mdBook](https://menhera-org.github.io/rs-l2tpd/).
