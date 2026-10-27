//! Shared construction of multicast sockets, tuned before notifications start.

use crate::config::TunnelConfig;
use futures_util::Stream;
use log::{debug, warn};
use rtnetlink::{
    packet_core::NetlinkMessage,
    packet_route::RouteNetlinkMessage,
    proto::Connection,
    sys::{AsyncSocket, Socket, SocketAddr},
    Handle, MulticastGroup,
};
use socket2::SockFilter;
use std::io;

/// Linux doubles SO_RCVBUF to account for skb bookkeeping. This request
/// therefore permits up to 16 MiB of queued kernel memory per monitor; it
/// does not allocate that memory eagerly or change a global kernel limit.
const REQUESTED_RECEIVE_BUFFER: usize = 8 * 1024 * 1024;

// Keep rtnetlink's constructor shape without adding a concrete channel dependency.
#[allow(clippy::type_complexity)]
pub(crate) fn multicast_connection(
    groups: &[MulticastGroup],
    purpose: &str,
    filter: Option<&[SockFilter]>,
) -> io::Result<(
    Connection<RouteNetlinkMessage>,
    Handle,
    impl Stream<Item = (NetlinkMessage<RouteNetlinkMessage>, SocketAddr)> + Unpin + Send + 'static,
)> {
    let (mut connection, mut handle, mut messages) = rtnetlink::new_connection()?;
    let previous = connection.socket_mut().socket_mut().get_rx_buf_sz().ok();
    if let Some(previous) = previous.filter(|size| *size < REQUESTED_RECEIVE_BUFFER * 2) {
        // Keep an untouched default socket until tuning has proved useful.
        // A host can have rmem_default > rmem_max; SO_RCVBUF would then shrink
        // its default, and an unavailable FORCE option could not restore it.
        match rtnetlink::new_connection() {
            Ok((mut candidate, candidate_handle, candidate_messages)) => {
                let socket = candidate.socket_mut().socket_mut();
                tune_receive_buffer(socket, purpose);
                if prefer_tuned_buffer(previous, socket.get_rx_buf_sz().ok()) {
                    (connection, handle, messages) =
                        (candidate, candidate_handle, candidate_messages);
                } else {
                    debug!("{purpose} keeps its original {previous}-byte receive buffer");
                }
            }
            Err(error) => debug!(
                "could not prepare a larger {purpose} receive buffer: {error}; keeping the default"
            ),
        }
    } else {
        debug!("{purpose} keeps its original receive buffer: {previous:?}");
    }
    let socket = connection.socket_mut().socket_mut();

    // A filter drops notifications in the kernel, before they take up any
    // of the buffer. Linux applies socket filters to netlink multicasts.
    // Attaching one needs no privilege; a failure only costs the filtering.
    if let Some(filter) = filter {
        match socket2::SockRef::from(&*socket).attach_filter(filter) {
            Ok(()) => debug!("{purpose} filters notifications in the kernel"),
            Err(error) => warn!(
                "could not attach the {purpose} notification filter: {error}; every notification of the subscribed groups will be read"
            ),
        }
    }

    // Match rtnetlink's multicast constructor, but tune the socket before
    // either bind or membership starts delivering notifications.
    let group_mask = groups
        .iter()
        .filter(|group| !group.need_via_add_membership())
        .fold(0, |mask, group| mask | (1 << (*group as u32 - 1)));
    socket.bind(&SocketAddr::new(0, group_mask))?;
    for group in groups
        .iter()
        .filter(|group| group.need_via_add_membership())
    {
        socket.add_membership(*group as u32)?;
    }
    Ok((connection, handle, messages))
}

fn prefer_tuned_buffer(previous: usize, tuned: Option<usize>) -> bool {
    tuned.is_some_and(|size| size >= previous)
}

fn tune_receive_buffer(socket: &Socket, purpose: &str) {
    let previous = socket.get_rx_buf_sz().ok();
    let target = REQUESTED_RECEIVE_BUFFER * 2;
    // A host may deliberately provide an even larger default. Never reduce it.
    if previous.is_some_and(|size| size >= target) {
        debug!(
            "{purpose} receive buffer already has {} bytes",
            previous.unwrap()
        );
        return;
    }

    if let Err(error) = socket.set_rx_buf_sz(REQUESTED_RECEIVE_BUFFER as libc::c_int) {
        warn!("failed to enlarge {purpose} receive buffer: {error}; continuing");
    }
    let ordinary = socket.get_rx_buf_sz().ok();
    if ordinary.is_none_or(|size| size < target) {
        // CAP_NET_ADMIN is already needed for daemon kernel operations.
        // Its absence, a seccomp policy, or a lower resource limit must not
        // turn this optional tuning into a new startup requirement.
        if let Err(error) = nix::sys::socket::setsockopt(
            socket,
            nix::sys::socket::sockopt::RcvBufForce,
            &REQUESTED_RECEIVE_BUFFER,
        ) {
            debug!("could not bypass the per-socket receive-buffer cap for {purpose}: {error}");
        }
    }
    match socket.get_rx_buf_sz() {
        Ok(effective) => debug!(
            "{purpose} receive buffer requested={} effective={} previous={previous:?} ordinary={ordinary:?}",
            REQUESTED_RECEIVE_BUFFER, effective
        ),
        Err(error) => debug!("could not read {purpose} receive buffer size: {error}"),
    }
}

/// A classic BPF instruction: code, jump offsets and constant.
type Instruction = (u16, u8, u8, u32);

/// Jump targets of the filter, resolved to offsets once the program is laid
/// out; classic BPF only jumps forward, to the instruction after the next.
#[derive(Clone, Copy)]
enum To {
    Next,
    Accept,
    Drop,
    Ipv4,
}

const RTM_NEWLINK: u32 = 16;
const RTM_DELLINK: u32 = 17;
const RTM_NEWADDR: u32 = 20;
const RTM_DELADDR: u32 = 21;
const RTM_DELROUTE: u32 = 25;
const RTA_DST: u32 = 1;
/// `sizeof(struct nlmsghdr)`, the offset of the netlink payload.
const NLMSG_HDRLEN: u32 = 16;
/// The offset of the route attributes: the payload's `struct rtmsg`
/// (family, dst_len, src_len, tos, table, protocol, scope, type, flags)
/// is 12 bytes long.
const RTM_ATTRS: u32 = NLMSG_HDRLEN + 12;
/// `ld #nla`: the ancillary load that finds the attribute of type X among
/// the attributes starting at offset A, leaving its offset (or 0) in A.
const NLATTR_LOAD: u32 = (libc::SKF_AD_OFF + libc::SKF_AD_NLATTR) as u32;

/// The notification filter of the route netlink monitor, as a classic BPF
/// program the kernel runs before queueing a notification.
///
/// It keeps link and address notifications and the replies to the
/// socket's own requests (the message types below `RTM_BASE`), and of the
/// route notifications only the removal of a discard route: `100::/128` or
/// `192.0.0.8/32`, whatever its table. Everything else, in particular the
/// churn of a full routing table, is dropped by the kernel before it takes
/// any of the receive buffer, so that routers do not overflow the monitor
/// on every table change.
pub(crate) fn monitor_filter() -> Vec<SockFilter> {
    monitor_filter_program()
        .into_iter()
        .map(|(code, jt, jf, k)| SockFilter::new(code, jt, jf, k))
        .collect()
}

fn monitor_filter_program() -> Vec<Instruction> {
    use libc::{
        BPF_ABS, BPF_B, BPF_H, BPF_IMM, BPF_IND, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_LDX,
        BPF_MISC, BPF_RET, BPF_TAX, BPF_W,
    };
    let stmt = |code: u32, k: u32| (code, k, To::Next, To::Next);
    let jump = |code: u32, k: u32, jt: To, jf: To| (code, k, jt, jf);
    let v6 = TunnelConfig::NO_PEER_ADDR.octets();
    let v6_words: [u32; 4] = std::array::from_fn(|i| {
        u32::from_be_bytes([v6[4 * i], v6[4 * i + 1], v6[4 * i + 2], v6[4 * i + 3]])
    });
    let v4 = u32::from_be_bytes(TunnelConfig::NO_PEER_ADDR_V4.octets());
    // BPF loads multi-byte fields in network byte order, while the netlink
    // header is in host byte order: compare the type as loaded.
    let host_u16 = |value: u32| u32::from(u16::from_be_bytes((value as u16).to_ne_bytes()));

    let mut program = vec![
        // A = nlmsg_type. The control messages (NLMSG_NOOP, NLMSG_ERROR,
        // NLMSG_DONE, NLMSG_OVERRUN) answer this socket's own requests.
        stmt(BPF_LD | BPF_H | BPF_ABS, 4),
        jump(BPF_JMP | BPF_JEQ | BPF_K, host_u16(1), To::Accept, To::Next),
        jump(BPF_JMP | BPF_JEQ | BPF_K, host_u16(2), To::Accept, To::Next),
        jump(BPF_JMP | BPF_JEQ | BPF_K, host_u16(3), To::Accept, To::Next),
        jump(BPF_JMP | BPF_JEQ | BPF_K, host_u16(4), To::Accept, To::Next),
        jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            host_u16(RTM_NEWLINK),
            To::Accept,
            To::Next,
        ),
        jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            host_u16(RTM_DELLINK),
            To::Accept,
            To::Next,
        ),
        jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            host_u16(RTM_NEWADDR),
            To::Accept,
            To::Next,
        ),
        jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            host_u16(RTM_DELADDR),
            To::Accept,
            To::Next,
        ),
        jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            host_u16(RTM_DELROUTE),
            To::Next,
            To::Drop,
        ),
        // A = rtm_family.
        stmt(BPF_LD | BPF_B | BPF_ABS, NLMSG_HDRLEN),
        jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            libc::AF_INET6 as u32,
            To::Next,
            To::Ipv4,
        ),
        // IPv6: a host route whose RTA_DST is 100::.
        stmt(BPF_LD | BPF_B | BPF_ABS, NLMSG_HDRLEN + 1),
        jump(BPF_JMP | BPF_JEQ | BPF_K, 128, To::Next, To::Drop),
        stmt(BPF_LDX | BPF_W | BPF_IMM, RTA_DST),
        stmt(BPF_LD | BPF_IMM, RTM_ATTRS),
        stmt(BPF_LD | BPF_W | BPF_ABS, NLATTR_LOAD),
        jump(BPF_JMP | BPF_JEQ | BPF_K, 0, To::Drop, To::Next),
        stmt(BPF_MISC | BPF_TAX, 0),
        stmt(BPF_LD | BPF_W | BPF_IND, 4),
        jump(BPF_JMP | BPF_JEQ | BPF_K, v6_words[0], To::Next, To::Drop),
        stmt(BPF_LD | BPF_W | BPF_IND, 8),
        jump(BPF_JMP | BPF_JEQ | BPF_K, v6_words[1], To::Next, To::Drop),
        stmt(BPF_LD | BPF_W | BPF_IND, 12),
        jump(BPF_JMP | BPF_JEQ | BPF_K, v6_words[2], To::Next, To::Drop),
        stmt(BPF_LD | BPF_W | BPF_IND, 16),
        jump(BPF_JMP | BPF_JEQ | BPF_K, v6_words[3], To::Accept, To::Drop),
    ];
    let ipv4_at = program.len();
    program.extend([
        // IPv4: a host route whose RTA_DST is 192.0.0.8. A still holds the
        // family here.
        jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            libc::AF_INET as u32,
            To::Next,
            To::Drop,
        ),
        stmt(BPF_LD | BPF_B | BPF_ABS, NLMSG_HDRLEN + 1),
        jump(BPF_JMP | BPF_JEQ | BPF_K, 32, To::Next, To::Drop),
        stmt(BPF_LDX | BPF_W | BPF_IMM, RTA_DST),
        stmt(BPF_LD | BPF_IMM, RTM_ATTRS),
        stmt(BPF_LD | BPF_W | BPF_ABS, NLATTR_LOAD),
        jump(BPF_JMP | BPF_JEQ | BPF_K, 0, To::Drop, To::Next),
        stmt(BPF_MISC | BPF_TAX, 0),
        stmt(BPF_LD | BPF_W | BPF_IND, 4),
        jump(BPF_JMP | BPF_JEQ | BPF_K, v4, To::Accept, To::Drop),
    ]);
    let accept_at = program.len();
    let drop_at = accept_at + 1;
    program.push(stmt(BPF_RET | BPF_K, u32::MAX));
    program.push(stmt(BPF_RET | BPF_K, 0));

    program
        .into_iter()
        .enumerate()
        .map(|(at, (code, k, jt, jf))| {
            let offset = |to: To| -> u8 {
                let target = match to {
                    To::Next => at + 1,
                    To::Accept => accept_at,
                    To::Drop => drop_at,
                    To::Ipv4 => ipv4_at,
                };
                u8::try_from(target - at - 1).expect("filter jumps are short")
            };
            (code as u16, offset(jt), offset(jf), k)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamped_or_unmeasurable_tuning_keeps_a_larger_original_buffer() {
        assert!(!prefer_tuned_buffer(1024 * 1024, Some(425984)));
        assert!(!prefer_tuned_buffer(212992, None));
        assert!(prefer_tuned_buffer(212992, Some(425984)));
        assert!(prefer_tuned_buffer(212992, Some(212992)));
    }

    #[tokio::test]
    async fn receive_buffer_tuning_is_bounded_and_needs_no_capability() {
        let baseline = Socket::new(rtnetlink::sys::protocols::NETLINK_ROUTE).unwrap();
        let before = baseline.get_rx_buf_sz().unwrap();
        let (mut connection, _handle, _messages) =
            multicast_connection(&[], "test monitor", Some(&monitor_filter())).unwrap();
        let after = connection
            .socket_mut()
            .socket_mut()
            .get_rx_buf_sz()
            .unwrap();
        assert!(
            after >= before,
            "buffer tuning must not shrink the kernel default"
        );
        assert!(after <= before.max(REQUESTED_RECEIVE_BUFFER * 2));
        eprintln!("netlink receive buffer: before={before} effective={after} requested={REQUESTED_RECEIVE_BUFFER}");
    }

    /// The attribute of type `kind` among the attributes at `start`, as the
    /// kernel's `nla_find` finds it for `ld #nla`.
    fn nla_find(data: &[u8], start: usize, kind: u32) -> u32 {
        let mut at = start;
        while at + 4 <= data.len() {
            let len = u16::from_ne_bytes([data[at], data[at + 1]]) as usize;
            let attr = u16::from_ne_bytes([data[at + 2], data[at + 3]]) as u32;
            if len < 4 || at + len > data.len() {
                break;
            }
            if attr & 0x3fff == kind {
                return at as u32;
            }
            at += len.next_multiple_of(4);
        }
        0
    }

    /// Runs a classic BPF program the way the kernel does on a packet.
    fn run(program: &[Instruction], data: &[u8]) -> u32 {
        let load = |offset: u32, size: u32| -> Option<u32> {
            let at = offset as usize;
            let bytes = match size {
                libc::BPF_B => 1,
                libc::BPF_H => 2,
                _ => 4,
            };
            let slice = data.get(at..at + bytes)?;
            Some(
                slice
                    .iter()
                    .fold(0u32, |value, byte| (value << 8) | u32::from(*byte)),
            )
        };
        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        loop {
            let (code, jt, jf, k) = program[pc];
            pc += 1;
            let code = u32::from(code);
            match code & 0x07 {
                libc::BPF_LD => {
                    a = match code & 0xe0 {
                        libc::BPF_IMM => k,
                        libc::BPF_ABS if k == NLATTR_LOAD => nla_find(data, a as usize, x),
                        libc::BPF_ABS => match load(k, code & 0x18) {
                            Some(value) => value,
                            None => return 0,
                        },
                        libc::BPF_IND => match load(x.wrapping_add(k), code & 0x18) {
                            Some(value) => value,
                            None => return 0,
                        },
                        mode => panic!("unexpected load mode {mode:#x}"),
                    }
                }
                libc::BPF_LDX => {
                    assert_eq!(code & 0xe0, libc::BPF_IMM);
                    x = k;
                }
                libc::BPF_JMP => {
                    let taken = match code & 0xf0 {
                        libc::BPF_JEQ => a == k,
                        libc::BPF_JGE => a >= k,
                        op => panic!("unexpected jump {op:#x}"),
                    };
                    pc += usize::from(if taken { jt } else { jf });
                }
                libc::BPF_RET => return k,
                libc::BPF_MISC => {
                    assert_eq!(code & 0xf8, libc::BPF_TAX);
                    x = a;
                }
                class => panic!("unexpected class {class:#x}"),
            }
        }
    }

    fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
        let len = 4 + value.len();
        let mut bytes = Vec::with_capacity(len.next_multiple_of(4));
        bytes.extend_from_slice(&(len as u16).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize(len.next_multiple_of(4), 0);
        bytes
    }

    fn message(message_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((16 + payload.len()) as u32).to_ne_bytes());
        bytes.extend_from_slice(&message_type.to_ne_bytes());
        bytes.extend_from_slice(&0u16.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    fn route(message_type: u16, family: u8, dst_len: u8, attributes: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut payload = vec![family, dst_len, 0, 0, 254, 2, 0, 1];
        payload.extend_from_slice(&0u32.to_ne_bytes());
        for (kind, value) in attributes {
            payload.extend(attribute(*kind, value));
        }
        message(message_type, &payload)
    }

    #[test]
    fn monitor_filter_keeps_link_address_and_discard_route_removals_only() {
        const RTM_NEWROUTE: u16 = 24;
        const RTA_TABLE: u16 = 15;
        const RTA_OIF: u16 = 4;
        let program = monitor_filter_program();
        assert!(program.len() <= 48);
        let accepts = |data: &[u8]| run(&program, data) != 0;
        let link = |message_type: u16| {
            let mut payload = vec![0u8; 16];
            payload.extend(attribute(3, b"eth0\0"));
            message(message_type, &payload)
        };
        for message_type in [RTM_NEWLINK, RTM_DELLINK, RTM_NEWADDR, RTM_DELADDR] {
            assert!(accepts(&link(message_type as u16)), "{message_type}");
        }
        // Replies to the socket's own requests: NLMSG_ERROR and NLMSG_DONE.
        assert!(accepts(&message(2, &[0; 20])));
        assert!(accepts(&message(3, &[0; 4])));

        let v6 = TunnelConfig::NO_PEER_ADDR.octets().to_vec();
        let v4 = TunnelConfig::NO_PEER_ADDR_V4.octets().to_vec();
        let table = 254u32.to_ne_bytes().to_vec();
        let oif = 7u32.to_ne_bytes().to_vec();
        let af_inet = libc::AF_INET as u8;
        let af_inet6 = libc::AF_INET6 as u8;
        // The discard route removals, with the destination attribute in
        // any position.
        for attributes in [
            vec![(RTA_TABLE, table.clone()), (RTA_DST as u16, v6.clone())],
            vec![(RTA_DST as u16, v6.clone()), (RTA_OIF, oif.clone())],
            vec![
                (RTA_TABLE, table.clone()),
                (RTA_OIF, oif.clone()),
                (RTA_DST as u16, v6.clone()),
            ],
        ] {
            assert!(accepts(&route(
                RTM_DELROUTE as u16,
                af_inet6,
                128,
                &attributes
            )));
        }
        for attributes in [
            vec![(RTA_TABLE, table.clone()), (RTA_DST as u16, v4.clone())],
            vec![(RTA_DST as u16, v4.clone())],
        ] {
            assert!(accepts(&route(
                RTM_DELROUTE as u16,
                af_inet,
                32,
                &attributes
            )));
        }

        let other_v6 = "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap();
        let near_v6 = "100::1".parse::<std::net::Ipv6Addr>().unwrap();
        let rejected = [
            // Additions, whatever they are.
            route(RTM_NEWROUTE, af_inet6, 128, &[(RTA_DST as u16, v6.clone())]),
            // Other prefixes and destinations.
            route(
                RTM_DELROUTE as u16,
                af_inet6,
                64,
                &[(RTA_DST as u16, v6.clone())],
            ),
            route(
                RTM_DELROUTE as u16,
                af_inet6,
                128,
                &[(RTA_DST as u16, other_v6.octets().to_vec())],
            ),
            route(
                RTM_DELROUTE as u16,
                af_inet6,
                128,
                &[(RTA_DST as u16, near_v6.octets().to_vec())],
            ),
            route(
                RTM_DELROUTE as u16,
                af_inet,
                24,
                &[(RTA_DST as u16, v4.clone())],
            ),
            route(
                RTM_DELROUTE as u16,
                af_inet,
                32,
                &[(RTA_DST as u16, vec![192, 0, 0, 9])],
            ),
            // The family's discard address under the other family.
            route(
                RTM_DELROUTE as u16,
                af_inet,
                32,
                &[(RTA_DST as u16, v6.clone())],
            ),
            // No destination at all, another family, a truncated message.
            route(RTM_DELROUTE as u16, af_inet6, 128, &[(RTA_TABLE, table)]),
            route(RTM_DELROUTE as u16, 28, 20, &[(RTA_DST as u16, v6.clone())]),
            route(RTM_DELROUTE as u16, af_inet6, 128, &[])[..24].to_vec(),
            message(RTM_DELROUTE as u16, &[]),
        ];
        for data in rejected {
            assert!(!accepts(&data), "{data:?}");
        }
    }

    #[tokio::test]
    #[ignore = "requires an isolated netns, CAP_NET_ADMIN and dummy support"]
    async fn privileged_monitor_filter_passes_link_and_discard_route_removals_only() {
        use futures_util::StreamExt;
        use l2tp::{L2tpIfName, L2tpIfNameExt};
        use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute};
        use rtnetlink::{LinkDummy, LinkUnspec, RouteMessageBuilder};
        use std::net::{Ipv4Addr, Ipv6Addr};
        use std::time::Duration;

        let (connection, _listener, mut messages) = multicast_connection(
            &[
                MulticastGroup::Link,
                MulticastGroup::Ipv4Route,
                MulticastGroup::Ipv6Route,
            ],
            "filtered test monitor",
            Some(&monitor_filter()),
        )
        .unwrap();
        let driver = tokio::spawn(connection);
        // The kernel does not echo a route notification to the port that
        // requested the change, so the changes go through another socket,
        // as the daemon's own do.
        let (operations, handle, _) = rtnetlink::new_connection().unwrap();
        let operations = tokio::spawn(operations);
        handle
            .link()
            .add(LinkDummy::new("rsl2tp-filter").up().build())
            .execute()
            .await
            .expect("privileged test requires dummy interfaces");
        let index = L2tpIfName::new("rsl2tp-filter").unwrap().index().unwrap();
        // Every route is added and removed; only the discard removals may
        // reach the socket, whatever else is in the message.
        let v6_routes: [(Ipv6Addr, u8); 4] = [
            ("2001:db8:200::".parse().unwrap(), 64),
            ("2001:db8:200::1".parse().unwrap(), 128),
            ("100::1".parse().unwrap(), 128),
            (TunnelConfig::NO_PEER_ADDR, 128),
        ];
        for (destination, prefix) in v6_routes {
            let route = RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(destination, prefix)
                .output_interface(index)
                .build();
            handle.route().add(route.clone()).execute().await.unwrap();
            handle.route().del(route).execute().await.unwrap();
        }
        let v4_routes: [(Ipv4Addr, u8); 3] = [
            ("198.51.100.0".parse().unwrap(), 24),
            ("198.51.100.9".parse().unwrap(), 32),
            (TunnelConfig::NO_PEER_ADDR_V4, 32),
        ];
        for (destination, prefix) in v4_routes {
            let route = RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(destination, prefix)
                .output_interface(index)
                .build();
            handle.route().add(route.clone()).execute().await.unwrap();
            handle.route().del(route).execute().await.unwrap();
        }
        handle
            .link()
            .set(
                LinkUnspec::new_with_index(index)
                    .name("rsl2tp-filtr2")
                    .build(),
            )
            .execute()
            .await
            .unwrap();
        handle.link().del(index).execute().await.unwrap();

        let (mut new_links, mut del_links, mut new_routes, mut del_routes) = (0, 0, 0, Vec::new());
        let deadline = tokio::time::sleep(Duration::from_millis(500));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                message = messages.next() => {
                    let Some((message, address)) = message else { break };
                    if address.port_number() != 0 {
                        continue;
                    }
                    let rtnetlink::packet_core::NetlinkPayload::InnerMessage(inner) = message.payload else {
                        continue;
                    };
                    match inner {
                        RouteNetlinkMessage::NewLink(link) if link.header.index == index => new_links += 1,
                        RouteNetlinkMessage::DelLink(link) if link.header.index == index => del_links += 1,
                        RouteNetlinkMessage::NewRoute(_) => new_routes += 1,
                        RouteNetlinkMessage::DelRoute(route) => {
                            let destination = route.attributes.iter().find_map(|attr| match attr {
                                RouteAttribute::Destination(RouteAddress::Inet(a)) => Some(std::net::IpAddr::V4(*a)),
                                RouteAttribute::Destination(RouteAddress::Inet6(a)) => Some(std::net::IpAddr::V6(*a)),
                                _ => None,
                            });
                            del_routes.push((destination, route.header.destination_prefix_length));
                        }
                        _ => {}
                    }
                }
                _ = &mut deadline => break,
            }
        }
        driver.abort();
        operations.abort();
        assert!(new_links >= 2, "creation and rename: {new_links}");
        assert_eq!(del_links, 1);
        assert_eq!(new_routes, 0, "route additions must be filtered out");
        assert_eq!(
            del_routes,
            vec![
                (Some(std::net::IpAddr::V6(TunnelConfig::NO_PEER_ADDR)), 128),
                (
                    Some(std::net::IpAddr::V4(TunnelConfig::NO_PEER_ADDR_V4)),
                    32
                ),
            ],
            "only the discard route removals may pass"
        );
    }
}
