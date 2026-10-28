//! The real kernel: tunnel sockets and generic netlink through `l2tp`,
//! rtnetlink requests and the subscriptions through `netlink-sys`. Every
//! function cites the kernel fact it relies on (`// kernel: ... (Kn)`).

mod bpf;
mod l2tp;
mod lifetime;
mod monitor;
mod rtnl;
mod socket;
