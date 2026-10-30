# l2tp 0.4.2 event sender fix (superseded by the 0.4.3 release)

`l2tp` 0.4.3, published 2026-10-28, shipped this fix (and `BoundedEvents`).
The daemon now depends on `l2tp` 0.5.0 and uses its own raw event transport.
The patch below is an archived reproduction against 0.4.2.

`l2tp-kernel-event-sender.patch` is the only upstream change prepared here.
It was developed in an isolated clone at commit
`9877db45bbeede95aae78e336156ce5860e2ae46`; the original event.rs matches
the cached published l2tp 0.4.2 source byte-for-byte. The sibling checkout
was not modified and nothing was published.

The event transport preserves recvmsg's SocketAddr but Events discarded it.
The patch ignores sender ports other than zero before decoding. A forged
zero port in the netlink header cannot bypass it. This fixes the stream's
kernel-notification trust boundary without changing public signatures,
default queue behavior, blocking iteration or request timeout semantics.
It is defense in depth, not a claim of an unprivileged kernel exploit.

The included regression fails without the filter and passes with it. In the
isolated clone, all 128 library tests and all-target/all-feature Clippy pass
for x86_64-unknown-linux-musl. See ../evidence/upstream-*.log.

Historical reproduction commands for the 0.4.2 checkout used above;
do not apply this already-shipped fix to current upstream:

```sh
git --no-pager apply --check /absolute/path/to/l2tp-kernel-event-sender.patch
git --no-pager apply /absolute/path/to/l2tp-kernel-event-sender.patch
cargo test --locked --target x86_64-unknown-linux-musl --lib
cargo clippy --locked --target x86_64-unknown-linux-musl --all-targets --all-features -- -D warnings
```

Unbounded event queues and calls without deadlines are not violations of the
existing upstream contracts. The daemon's Phase 2 design uses its own bounded
raw-netlink transport with existing packet codecs; it does not require changing
l2tp's defaults for this consumer.
