//! The event monitor: link and address groups, the filter, `ENOBUFS` as a
//! loss (spec A5, K10, K29, E20–E22), and the reader both notification
//! subscriptions share.
//!
//! The socket is opened where the subscription is created, on the
//! reconciler's thread, and registered with the reactor of the runtime
//! that first polls it: the trait creates and polls on different threads.

use std::collections::VecDeque;
use std::io;
use std::task::{Context, Poll};

use netlink_sys::Socket;
use netlink_sys::protocols::NETLINK_ROUTE;
use nix::libc;
use socket2::SockRef;
use tokio::io::unix::AsyncFd;

use super::bpf;
use super::request::{Msg, messages, subscribe};
use super::rtnl::{parse_addr, parse_link};
use crate::kernel::{Notice, Subscription};

/// Turns one kernel message into a notice, if it is one.
pub(super) type Decode = Box<dyn Fn(&Msg<'_>) -> Option<Notice> + Send>;
/// Opens the subscription's socket again after a failure (A13).
pub(super) type Reopen = Box<dyn FnMut() -> io::Result<Socket> + Send>;

/// A subscription read straight from its kernel socket: what waits is in
/// the socket's buffer, bounded by it (E20).
pub(super) struct Feed {
    opened: Option<Socket>,
    registered: Option<AsyncFd<Socket>>,
    pending: VecDeque<Notice>,
    decode: Decode,
    reopen: Reopen,
}

impl Feed {
    // kernel: net/netlink/af_netlink.c netlink_recvmsg (K29)
    pub(super) fn new(socket: Socket, decode: Decode, reopen: Reopen) -> Self {
        Feed {
            opened: Some(socket),
            registered: None,
            pending: VecDeque::new(),
            decode,
            reopen,
        }
    }

    // kernel: (K29, K30) net/netlink/af_netlink.c netlink_recvmsg; the sender's
    // port is 0 for the kernel, and only CAP_NET_ADMIN can unicast here
    /// Queues the notices of one datagram; a broken one is a loss.
    fn receive(&mut self, datagram: &[u8]) {
        match messages(datagram) {
            Ok(msgs) => self.pending.extend(msgs.iter().filter_map(&self.decode)),
            Err(_) => self.pending.push_back(Notice::Loss),
        }
    }
}

impl Subscription for Feed {
    // kernel: (K29) net/netlink/af_netlink.c netlink_overrun, sock_error:
    // ENOBUFS once per overflow, then the queue continues
    fn poll_notice(&mut self, cx: &mut Context<'_>) -> Poll<Notice> {
        loop {
            if let Some(notice) = self.pending.pop_front() {
                return Poll::Ready(notice);
            }
            let Some(fd) = &self.registered else {
                let socket = match self.opened.take().map_or_else(&mut self.reopen, Ok) {
                    Ok(socket) => socket,
                    Err(error) => {
                        // shortcut: retried at every poll; pace it with a timer if
                        // reopening ever fails for long (descriptor exhaustion).
                        log::warn!("netlink subscription cannot be reopened: {error}");
                        cx.waker().wake_by_ref();
                        return Poll::Ready(Notice::Loss);
                    }
                };
                // `register` is the unsafe spelling of the same call; its
                // condition holds, `Socket` owns the descriptor it reports.
                #[allow(deprecated)]
                let registered = AsyncFd::new(socket);
                match registered {
                    Ok(fd) => self.registered = Some(fd),
                    Err(error) => {
                        log::warn!("netlink subscription cannot be registered: {error}");
                        cx.waker().wake_by_ref();
                        return Poll::Ready(Notice::Loss);
                    }
                }
                continue;
            };
            let mut guard = match fd.poll_read_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(error)) => {
                    log::warn!("netlink subscription failed, reopening: {error}");
                    self.registered = None;
                    return Poll::Ready(Notice::Loss);
                }
            };
            match guard.try_io(|fd| fd.get_ref().recv_from_full()) {
                Err(_would_block) => {}
                Ok(Ok((datagram, from))) => {
                    if from.port_number() == 0 {
                        self.receive(&datagram); // E22
                    }
                }
                Ok(Err(error)) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                    return Poll::Ready(Notice::Loss); // E21
                }
                Ok(Err(error)) => {
                    log::warn!("netlink subscription failed, reopening: {error}");
                    self.registered = None;
                    return Poll::Ready(Notice::Loss);
                }
            }
        }
    }
}

// kernel: (K7, K10) net/core/rtnetlink.c rtmsg_ifinfo (RTNLGRP_LINK),
// net/ipv4/devinet.c rtmsg_ifa, net/ipv6/addrconf.c inet6_ifa_notify; no route
// group; net/core/filter.c sk_attach_filter
/// The monitor's socket, filtered when the host allows it (R6).
fn socket() -> io::Result<Socket> {
    let socket = subscribe(
        NETLINK_ROUTE,
        &[
            libc::RTNLGRP_LINK,
            libc::RTNLGRP_IPV4_IFADDR,
            libc::RTNLGRP_IPV6_IFADDR,
        ],
    )?;
    if let Err(error) = SockRef::from(&socket).attach_filter(&bpf::filter()) {
        log::warn!("event monitor runs unfiltered: {error}");
    }
    Ok(socket)
}

// kernel: (K7) net/core/rtnetlink.c rtnl_fill_ifinfo (ifi_family AF_UNSPEC for
// a device, AF_BRIDGE or AF_INET6 for protocol state)
/// The monitor's notices; the filter's choice applied again, since the
/// host may refuse the filter (E5, R6).
fn decode(msg: &Msg<'_>) -> Option<Notice> {
    match msg.kind {
        libc::RTM_NEWLINK | libc::RTM_DELLINK => {
            let link = parse_link(msg.payload)?;
            (link.family == libc::AF_UNSPEC as u8).then_some(())?;
            Some(if msg.kind == libc::RTM_NEWLINK {
                Notice::LinkNew(link.info)
            } else {
                Notice::LinkDel(link.info)
            })
        }
        libc::RTM_NEWADDR => parse_addr(msg.payload).map(Notice::AddrNew),
        libc::RTM_DELADDR => parse_addr(msg.payload).map(Notice::AddrDel),
        _ => None,
    }
}

// kernel: net/netlink/af_netlink.c netlink_add_membership (K7, K10, K29)
/// Opens the event monitor (A5).
pub(super) fn monitor() -> io::Result<Feed> {
    Ok(Feed::new(socket()?, Box::new(decode), Box::new(socket)))
}
