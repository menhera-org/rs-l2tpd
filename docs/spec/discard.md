# Discard addresses (retired)

[Specification index](README.md)

Requirements D1–D13 are withdrawn; their numbers are never reused.
Tunnels without a reachable peer remain disconnected, and the kernel drops
their outbound frames ([K5](kernel.md#requirements),
[T1](tunnels.md#the-right-state-of-a-tunnel)). No discard address, null
device or route repair is used. Names `rsl2tpnull*` are not reserved
([R19](requirements.md#the-operator)).

The retired design and rationale remain in
[Git history](https://github.com/menhera-org/rs-l2tpd/blob/c599b1f9c2343a3ffe6be315a6d77c4b68106744/docs/spec/discard.md).
