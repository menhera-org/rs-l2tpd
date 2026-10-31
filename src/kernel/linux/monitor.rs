//! The event monitor: link and address groups, the filter, `ENOBUFS` as a
//! loss (spec A5, K10, K29, E20–E22), and the reader both notification
//! subscriptions share.
//!
//! The socket is opened where the subscription is created, on the
//! reconciler's thread, and registered with the reactor of the runtime
//! that first polls it: the trait creates and polls on different threads.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
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
    retry: Option<Pin<Box<tokio::time::Sleep>>>,
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
            retry: None,
        }
    }

    // kernel: (K29, K30) net/netlink/af_netlink.c netlink_recvmsg; the sender's
    // port is 0 for the kernel, and only CAP_NET_ADMIN can unicast here
    /// Queues the notices of one datagram; a broken one is a loss.
    fn receive(&mut self, datagram: &[u8]) {
        match messages(datagram) {
            Ok(msgs) => self.pending.extend(msgs.iter().filter_map(|msg| {
                if msg.kind == netlink_packet_core::NLMSG_OVERRUN {
                    Some(Notice::Loss)
                } else {
                    (self.decode)(msg)
                }
            })),
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
            if let Some(retry) = &mut self.retry {
                if retry.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                self.retry = None;
            }
            let Some(fd) = &self.registered else {
                let socket = match self.opened.take().map_or_else(&mut self.reopen, Ok) {
                    Ok(socket) => socket,
                    Err(error) => {
                        log::warn!("netlink subscription cannot be reopened: {error}");
                        self.retry = Some(Box::pin(tokio::time::sleep(
                            std::time::Duration::from_secs(1),
                        )));
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
                        self.retry = Some(Box::pin(tokio::time::sleep(
                            std::time::Duration::from_secs(1),
                        )));
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
        let errno = nix::errno::Errno::from_raw(crate::kernel::errno(&error));
        log::warn!("event monitor runs unfiltered: {errno:?}: {error}");
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    // kernel: (K29) include/uapi/linux/netlink.h NLMSG_OVERRUN and framing.
    /// spec: E20, E21, E22, A13
    #[test]
    fn broken_datagrams_and_reopen_failure_keep_loss_observable() {
        for kind in [
            netlink_packet_core::NLMSG_DONE,
            libc::RTM_NEWLINK,
            libc::RTM_DELLINK,
            libc::RTM_NEWADDR,
            libc::RTM_DELADDR,
        ] {
            assert!(
                decode(&Msg {
                    kind,
                    flags: 0,
                    seq: 0,
                    payload: &[]
                })
                .is_none()
            );
        }
        let socket = super::super::request::open(NETLINK_ROUTE).unwrap();
        let mut feed = Feed::new(
            socket,
            Box::new(decode),
            Box::new(|| Err(io::Error::from_raw_os_error(libc::EMFILE))),
        );
        let mut header = [0; 16];
        header[..4].copy_from_slice(&16u32.to_ne_bytes());
        header[4..6].copy_from_slice(&netlink_packet_core::NLMSG_OVERRUN.to_ne_bytes());
        feed.receive(&[0]);
        feed.receive(&header);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut cx = Context::from_waker(std::task::Waker::noop());
            assert_eq!(feed.poll_notice(&mut cx), Poll::Ready(Notice::Loss));
            assert_eq!(feed.poll_notice(&mut cx), Poll::Ready(Notice::Loss));
            feed.opened.take();
            assert_eq!(feed.poll_notice(&mut cx), Poll::Ready(Notice::Loss));
            assert!(feed.poll_notice(&mut cx).is_pending());
            let notice = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                std::future::poll_fn(|cx| feed.poll_notice(cx)),
            )
            .await
            .unwrap();
            assert_eq!(notice, Notice::Loss);
        });
    }

    // kernel: net/netlink/af_netlink.c netlink_sendmsg, netlink_recvmsg
    // (K29, K30); the userspace sender's address must be checked (E22)
    /// spec: E22, K30
    #[test]
    #[ignore = "isolated network namespace with CAP_NET_ADMIN"]
    fn a_live_feed_ignores_a_forged_notification_before_a_real_one() {
        use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload};
        use netlink_packet_route::{
            RouteNetlinkMessage,
            link::{LinkAttribute, LinkMessage},
        };
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
        let mut feed = monitor().unwrap();
        let mut address = netlink_sys::SocketAddr::new(0, 0);
        feed.opened
            .as_ref()
            .unwrap()
            .get_address(&mut address)
            .unwrap();
        let sender = super::super::request::open(NETLINK_ROUTE).unwrap();
        let mut link = LinkMessage::default();
        link.header.index = 999;
        link.attributes.push(LinkAttribute::IfName("forged".into()));
        let mut message = NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)),
        );
        message.finalize();
        let mut bytes = vec![0; message.buffer_len()];
        message.serialize(&mut bytes);
        sender.send_to(&bytes, &address, 0).unwrap();
        let output = std::process::Command::new("ip")
            .args(["link", "add", "name", "actual", "type", "dummy"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let notice = runtime.block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                std::future::poll_fn(|cx| feed.poll_notice(cx)),
            )
            .await
            .unwrap()
        });
        assert!(matches!(notice, Notice::LinkNew(link) if link.name.to_string_lossy() == "actual"));
    }

    // kernel: (K29, K36) recv errors invalidate the feed; reactor registration can fail independently.
    /// spec: A13, E20, E21, G12, L9
    #[test]
    #[ignore = "serial isolated live runner; child forks must not inherit concurrent fake descriptors"]
    fn registration_and_receive_failures_preserve_loss_and_retry_bounds() {
        const CHILD: &str = "PHASE6_FEED_FAULT";
        if let Ok(case) = std::env::var(CHILD) {
            if case == "open" {
                super::super::syscall_fault::refuse(&[libc::SYS_socket], libc::EMFILE);
                assert_eq!(monitor().err().unwrap().raw_os_error(), Some(libc::EMFILE));
                println!("FEED_FAULT_CHECKED={case}");
                return;
            }
            use netlink_packet_core::{
                NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
            };
            use netlink_packet_route::{RouteNetlinkMessage, link::LinkMessage};
            use std::sync::{
                Arc,
                atomic::{AtomicUsize, Ordering},
            };
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let opened = super::super::request::open(NETLINK_ROUTE).unwrap();
            let mut header = NetlinkHeader::default();
            header.flags = NLM_F_REQUEST;
            let mut request = NetlinkMessage::new(
                header,
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::GetLink(LinkMessage::default())),
            );
            request.finalize();
            let mut bytes = vec![0; request.buffer_len()];
            request.serialize(&mut bytes);
            opened.send(&bytes, 0).unwrap();
            let attempts = Arc::new(AtomicUsize::new(0));
            let reopened = attempts.clone();
            let mut feed = Feed::new(
                opened,
                Box::new(decode),
                Box::new(move || {
                    reopened.fetch_add(1, Ordering::SeqCst);
                    super::super::request::open(NETLINK_ROUTE)
                }),
            );
            match case.as_str() {
                "registration" => {
                    super::super::syscall_fault::refuse(&[libc::SYS_epoll_ctl], libc::EPERM)
                }
                "overflow" => {
                    super::super::syscall_fault::refuse(&[libc::SYS_recvfrom], libc::ENOBUFS)
                }
                "receive" => super::super::syscall_fault::refuse(&[libc::SYS_recvfrom], libc::EIO),
                _ => panic!("unknown feed fault"),
            }
            runtime.block_on(async {
                let next = std::future::poll_fn(|cx| feed.poll_notice(cx));
                assert_eq!(
                    tokio::time::timeout(std::time::Duration::from_secs(3), next)
                        .await
                        .unwrap(),
                    Notice::Loss
                );
                assert_eq!(attempts.load(Ordering::SeqCst), 0);
                if case == "registration" {
                    assert!(feed.registered.is_none());
                    let retry = feed.retry.as_ref().unwrap().deadline();
                    let next = std::future::poll_fn(|cx| feed.poll_notice(cx));
                    assert_eq!(
                        tokio::time::timeout(std::time::Duration::from_secs(3), next)
                            .await
                            .unwrap(),
                        Notice::Loss
                    );
                    assert!(tokio::time::Instant::now() >= retry);
                    assert_eq!(attempts.load(Ordering::SeqCst), 1);
                } else {
                    assert_eq!(feed.registered.is_some(), case == "overflow");
                    assert!(feed.retry.is_none());
                }
            });
            println!("FEED_FAULT_CHECKED={case}");
            return;
        }
        for case in ["open", "registration", "overflow", "receive"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "kernel::linux::monitor::tests::registration_and_receive_failures_preserve_loss_and_retry_bounds", "--nocapture", "--test-threads=1"])
                .env(CHILD, case).output().unwrap();
            assert!(output.status.success(), "{case}: {output:?}");
            assert!(
                String::from_utf8_lossy(&output.stdout)
                    .contains(&format!("FEED_FAULT_CHECKED={case}"))
            );
            println!("FEED_FAULT_VERIFIED={case}");
        }
    }

    // kernel: (K29) the old subscription cannot deliver after its reactor has shut down.
    /// spec: A13, E20
    #[test]
    fn reactor_shutdown_reports_loss_before_reopening_on_the_next_runtime() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let attempts = Arc::new(AtomicUsize::new(0));
        let reopened = attempts.clone();
        let socket = super::super::request::open(NETLINK_ROUTE).unwrap();
        let mut feed = Feed::new(
            socket,
            Box::new(decode),
            Box::new(move || {
                reopened.fetch_add(1, Ordering::SeqCst);
                super::super::request::open(NETLINK_ROUTE)
            }),
        );
        let first = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        first.block_on(std::future::poll_fn(|cx| {
            assert!(feed.poll_notice(cx).is_pending());
            Poll::Ready(())
        }));
        assert!(feed.registered.is_some());
        drop(first);
        let second = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        second.block_on(std::future::poll_fn(|cx| {
            assert_eq!(feed.poll_notice(cx), Poll::Ready(Notice::Loss));
            assert!(feed.registered.is_none());
            assert!(feed.poll_notice(cx).is_pending());
            Poll::Ready(())
        }));
        assert!(feed.registered.is_some());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }
}
