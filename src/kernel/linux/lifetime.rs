//! The link-lifetime subscription and its ordered lookups (spec A7, S8,
//! S9, M18).
//!
//! A thread of its own reads the socket continuously, so that a busy
//! reconciler never starves it. It keeps the generation, the armed
//! captures and the tracked registrations, nothing about foreign devices.
//! The reconciler's thread arms a capture before a session creation and
//! sends lookups on the same socket, so that the kernel queues each reply
//! after every notification queued before it (A7); the thread answers
//! through the shared state.
//!
//! A new generation needs no seed: nothing captured in an ended one is
//! provable, and a new registration is captured from its own broadcast.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use netlink_packet_core::{
    NLM_F_REQUEST, NLMSG_ERROR, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_packet_route::link::LinkMessage;
use netlink_sys::protocols::NETLINK_ROUTE;
use netlink_sys::{Socket, SocketAddr};
use nix::libc;

use super::request::{DEADLINE, errno, messages, subscribe, wait};
use super::rtnl::parse_link;
use crate::kernel::{L2tpIfName, Proof, Registration};

/// How long the thread waits before it checks for a stop or a new socket.
const TICK: Duration = Duration::from_secs(1);

/// A capture armed for a creation name (S8).
enum Capture {
    Armed,
    /// The first registration broadcast: index and incarnation.
    Seen(u32, u64),
}

/// The answer to a lookup.
#[derive(Clone, Copy)]
enum Answer {
    Pending,
    Found,
    /// `ENODEV`: no device has the index.
    Absent,
    /// Any other error: nothing is known.
    Failed,
}

/// A registration still tracked: its index, and whether a removal of the
/// index was seen since.
struct Tracked {
    index: u32,
    removed: bool,
}

struct State {
    stop: bool,
    generation: u64,
    /// The generation's socket; `None` while it cannot be reopened.
    socket: Option<Arc<Socket>>,
    incarnations: u64,
    seq: u32,
    captures: HashMap<L2tpIfName, Capture>,
    tracked: HashMap<u64, Tracked>,
    lookups: HashMap<u32, Answer>,
}

impl State {
    // kernel: net/netlink/af_netlink.c netlink_overrun (K29, K36)
    /// Ends the generation (E20, M18): nothing captured in it is provable,
    /// and a new socket takes over.
    fn end_generation(&mut self) {
        self.generation += 1;
        self.captures.clear();
        self.tracked.clear();
        self.lookups.clear();
        self.socket = open().map(Arc::new).ok();
    }

    // kernel: (K16, K20, K29, K30) net/core/dev.c:10425 register_netdevice and
    // 11205-11224 unregister (RTM_NEWLINK, RTM_DELLINK with ifi_family
    // AF_UNSPEC, also on a move to another namespace, 11380);
    // net/l2tp/l2tp_eth.c:300-310 (the device is registered under rtnl before
    // its name is stored); replies to lookups are unicast (nl_groups 0) with
    // the request's seq
    /// Applies one datagram.
    fn receive(&mut self, datagram: &[u8], from: &SocketAddr) {
        if from.port_number() != 0 {
            return; // E22
        }
        let unicast = from.multicast_groups() == 0;
        let Ok(msgs) = messages(datagram) else {
            log::warn!("lifetime subscription: a broken datagram");
            return self.end_generation();
        };
        for msg in msgs {
            if unicast {
                if let Some(answer) = self.lookups.get_mut(&msg.seq) {
                    *answer = match msg.kind {
                        libc::RTM_NEWLINK => Answer::Found,
                        NLMSG_ERROR
                            if msg.payload.get(..4) == Some(&(-libc::ENODEV).to_ne_bytes()) =>
                        {
                            Answer::Absent
                        }
                        _ => Answer::Failed,
                    };
                }
                continue;
            }
            let Some(link) = parse_link(msg.payload) else {
                continue;
            };
            if link.family != libc::AF_UNSPEC as u8 {
                continue; // E5
            }
            let index = link.info.index;
            match msg.kind {
                libc::RTM_NEWLINK => {
                    if let Some(capture @ Capture::Armed) = self.captures.get_mut(&link.info.name) {
                        self.incarnations += 1;
                        let incarnation = self.incarnations;
                        *capture = Capture::Seen(index, incarnation);
                        self.tracked.insert(
                            incarnation,
                            Tracked {
                                index,
                                removed: false,
                            },
                        );
                    }
                }
                libc::RTM_DELLINK => {
                    for tracked in self.tracked.values_mut().filter(|t| t.index == index) {
                        tracked.removed = true;
                    }
                }
                _ => {}
            }
        }
    }
}

// kernel: net/core/rtnetlink.c rtmsg_ifinfo (RTNLGRP_LINK), never filtered (K7, K29, K36)
fn open() -> io::Result<Socket> {
    subscribe(NETLINK_ROUTE, &[libc::RTNLGRP_LINK])
}

// kernel: (K29) net/core/rtnetlink.c rtnl_getlink (3929-: by ifi_index, the
// reply to the requester's port with its seq, ENODEV when absent)
/// Sends a lookup of `index` on the lifetime socket, without an ACK.
fn send_lookup(socket: &Socket, seq: u32, index: u32) -> io::Result<()> {
    let mut link = LinkMessage::default();
    link.header.index = index;
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST;
    header.sequence_number = seq;
    let payload = NetlinkPayload::InnerMessage(RouteNetlinkMessage::GetLink(link));
    let mut message = NetlinkMessage::new(header, payload);
    message.finalize();
    let mut buffer = vec![0; message.buffer_len()];
    message.serialize(&mut buffer);
    socket.send(&buffer, 0).map(drop)
}

struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

impl Shared {
    // kernel: net/netlink/af_netlink.c netlink_recvmsg (K29)
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    // kernel: net/netlink/af_netlink.c netlink_recvmsg (K29)
    /// Waits for a change until `deadline`; `false` when it passed.
    fn wait_until<'a>(
        &self,
        state: MutexGuard<'a, State>,
        deadline: Instant,
    ) -> (MutexGuard<'a, State>, bool) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return (state, false);
        }
        let (state, _) = self
            .changed
            .wait_timeout(state, left)
            .unwrap_or_else(PoisonError::into_inner);
        (state, true)
    }
}

// kernel: (K29) net/netlink/af_netlink.c netlink_recvmsg, netlink_overrun
// (ENOBUFS ends the generation)
/// The reading thread.
fn read(shared: Arc<Shared>) {
    loop {
        let (generation, socket) = {
            let mut state = shared.lock();
            if state.stop {
                return;
            }
            if state.socket.is_none() {
                state.socket = open().map(Arc::new).ok();
            }
            (state.generation, state.socket.clone())
        };
        let Some(socket) = socket else {
            std::thread::sleep(TICK);
            continue;
        };
        if let Err(error) = wait(&socket, Instant::now() + TICK)
            && error.raw_os_error() != Some(libc::ETIMEDOUT)
        {
            log::warn!("lifetime subscription: {error}");
        }
        loop {
            let received = socket.recv_from_full();
            if matches!(&received, Err(e) if e.kind() == io::ErrorKind::WouldBlock) {
                break;
            }
            let mut state = shared.lock();
            if state.generation != generation {
                break;
            }
            match received {
                Ok((datagram, from)) => state.receive(&datagram, &from),
                Err(error) => {
                    log::warn!("lifetime subscription lost notifications: {error}");
                    state.end_generation();
                }
            }
            shared.changed.notify_all();
        }
    }
}

/// The lifetime subscription (A7).
pub(super) struct Lifetime {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl Lifetime {
    // kernel: net/core/rtnetlink.c rtmsg_ifinfo (K7, K36)
    /// Opens the socket and starts the thread; the first generation is 0.
    pub(super) fn new() -> io::Result<Self> {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                stop: false,
                generation: 0,
                socket: Some(Arc::new(open()?)),
                incarnations: 0,
                seq: 0,
                captures: HashMap::new(),
                tracked: HashMap::new(),
                lookups: HashMap::new(),
            }),
            changed: Condvar::new(),
        });
        let reader = shared.clone();
        let thread = std::thread::Builder::new()
            .name("rs-l2tpd-lifetime".into())
            .spawn(move || read(reader))?;
        Ok(Lifetime {
            shared,
            thread: Some(thread),
        })
    }

    // kernel: (K16, K20) net/l2tp/l2tp_eth.c:300-310 (the name is unique when
    // the device registers, K20)
    /// Arms the capture of `name` before its creation request (S8); the
    /// generation it belongs to.
    pub(super) fn arm(&self, name: &L2tpIfName) -> io::Result<u64> {
        let mut state = self.shared.lock();
        if state.socket.is_none() {
            return Err(errno(libc::ENOBUFS));
        }
        if state.captures.contains_key(name) {
            return Err(errno(libc::EEXIST));
        }
        state.captures.insert(*name, Capture::Armed);
        Ok(state.generation)
    }

    // kernel: net/core/dev.c:10425 (the registration broadcast) (K20)
    /// The registration captured for `name` by `deadline`; `ETIMEDOUT` when
    /// it was not seen or the generation ended (an uncertain creation).
    /// Disarms the capture.
    pub(super) fn capture(
        &self,
        name: &L2tpIfName,
        generation: u64,
        deadline: Instant,
    ) -> io::Result<Registration> {
        let mut state = self.shared.lock();
        let result = loop {
            if state.generation != generation {
                break Err(errno(libc::ETIMEDOUT));
            }
            if let Some(&Capture::Seen(index, incarnation)) = state.captures.get(name) {
                break Ok(Registration {
                    index,
                    generation,
                    incarnation,
                });
            }
            let (next, waited) = self.shared.wait_until(state, deadline);
            state = next;
            if !waited {
                break Err(errno(libc::ETIMEDOUT));
            }
        };
        state.captures.remove(name);
        result
    }

    // kernel: net/core/dev.c:10425 (K20)
    /// Disarms the capture of a creation the kernel refused; what it saw
    /// was a foreign device of that name.
    pub(super) fn disarm(&self, name: &L2tpIfName) {
        let mut state = self.shared.lock();
        if let Some(Capture::Seen(_, incarnation)) = state.captures.remove(name) {
            state.tracked.remove(&incarnation);
        }
    }

    // kernel: (K29) net/core/rtnetlink.c rtnl_getlink, answered after every
    // notification queued before it; dev.c:11205-11224 (RTM_DELLINK)
    /// The ordered proof of S9: removed when a removal of the index was
    /// seen or the lookup finds no device; lost when the generation ended
    /// or the reply did not come within the deadline (E21).
    pub(super) fn prove(&self, registration: &Registration) -> Proof {
        let deadline = Instant::now() + DEADLINE;
        let (seq, socket) = {
            let mut state = self.shared.lock();
            if state.generation != registration.generation {
                return Proof::Lost;
            }
            match state.tracked.get(&registration.incarnation) {
                None => return Proof::Lost,
                Some(tracked) if tracked.removed => return Proof::Removed,
                Some(_) => {}
            }
            let Some(socket) = state.socket.clone() else {
                return Proof::Lost;
            };
            state.seq = state.seq.wrapping_add(1).max(1);
            let seq = state.seq;
            state.lookups.insert(seq, Answer::Pending);
            (seq, socket)
        };
        let sent = send_lookup(&socket, seq, registration.index);
        let mut state = self.shared.lock();
        if let Err(error) = sent {
            log::warn!("lifetime lookup failed: {error}");
            if state.generation == registration.generation {
                state.end_generation();
            }
            return Proof::Lost;
        }
        loop {
            if state.generation != registration.generation {
                return Proof::Lost;
            }
            let answer = state.lookups.get(&seq).copied().unwrap_or(Answer::Failed);
            let removed = |state: &mut State| {
                if let Some(tracked) = state.tracked.get_mut(&registration.incarnation) {
                    tracked.removed = true;
                }
                Proof::Removed
            };
            match answer {
                Answer::Pending => {}
                Answer::Found => {
                    state.lookups.remove(&seq);
                    let tracked = state.tracked.get(&registration.incarnation);
                    return match tracked {
                        Some(tracked) if !tracked.removed => Proof::Proved,
                        Some(_) => Proof::Removed,
                        None => Proof::Lost,
                    };
                }
                Answer::Absent => {
                    state.lookups.remove(&seq);
                    return removed(&mut state);
                }
                Answer::Failed => {
                    state.lookups.remove(&seq);
                    return Proof::Lost;
                }
            }
            let (next, waited) = self.shared.wait_until(state, deadline);
            state = next;
            if !waited {
                log::warn!("lifetime lookup unanswered for {DEADLINE:?}: generation ends");
                state.end_generation();
                return Proof::Lost;
            }
        }
    }

    // kernel: net/core/dev.c:11205-11224 (K29)
    /// Stops tracking a registration.
    pub(super) fn release(&self, registration: &Registration) {
        self.shared.lock().tracked.remove(&registration.incarnation);
    }
}

impl Drop for Lifetime {
    // kernel: (K29) net/core/rtnetlink.c rtnl_getlink (EINVAL for no index and
    // no name: a reply that wakes the thread)
    fn drop(&mut self) {
        let socket = {
            let mut state = self.shared.lock();
            state.stop = true;
            state.socket.clone()
        };
        if let Some(socket) = socket {
            let _ = send_lookup(&socket, 0, 0);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // kernel: include/uapi/linux/rtnetlink.h struct ifinfomsg (K20)
    fn link(kind: u16, family: u8, index: u32, name: &[u8]) -> Vec<u8> {
        let mut payload = vec![family, 0, 1, 0];
        payload.extend_from_slice(&index.to_ne_bytes());
        payload.extend_from_slice(&[0; 8]);
        let len = 4 + name.len() + 1;
        payload.extend_from_slice(&(len as u16).to_ne_bytes());
        payload.extend_from_slice(&libc::IFLA_IFNAME.to_ne_bytes());
        payload.extend_from_slice(name);
        payload.push(0);
        payload.resize(payload.len().next_multiple_of(4), 0);
        let mut out = ((16 + payload.len()) as u32).to_ne_bytes().to_vec();
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(&[0; 10]);
        out.extend(payload);
        out
    }

    // kernel: net/core/rtnetlink.c rtmsg_ifinfo (K20)
    fn state() -> State {
        State {
            stop: false,
            generation: 0,
            socket: None,
            incarnations: 0,
            seq: 0,
            captures: HashMap::new(),
            tracked: HashMap::new(),
            lookups: HashMap::new(),
        }
    }

    // kernel: net/core/dev.c:10425, 11205-11224 (K16, K20)
    /// spec: S8, S9, M18, E5, E22
    #[test]
    fn a_capture_takes_the_first_broadcast_and_a_removal_sticks() {
        let kernel = SocketAddr::new(0, libc::RTNLGRP_LINK);
        let name = L2tpIfName::new(b"rsl2tp-t000001").unwrap();
        let mut state = state();
        state.captures.insert(name, Capture::Armed);
        state.receive(
            &link(
                libc::RTM_NEWLINK,
                libc::AF_BRIDGE as u8,
                7,
                b"rsl2tp-t000001",
            ),
            &kernel,
        );
        state.receive(
            &link(libc::RTM_NEWLINK, 0, 8, b"rsl2tp-t000001"),
            &SocketAddr::new(99, 1),
        );
        assert!(matches!(state.captures[&name], Capture::Armed));
        state.receive(&link(libc::RTM_NEWLINK, 0, 8, b"rsl2tp-t000001"), &kernel);
        state.receive(&link(libc::RTM_NEWLINK, 0, 9, b"rsl2tp-t000001"), &kernel);
        assert!(matches!(state.captures[&name], Capture::Seen(8, 1)));
        state.receive(&link(libc::RTM_DELLINK, 0, 8, b"rsl2tp-t000001"), &kernel);
        state.receive(&link(libc::RTM_NEWLINK, 0, 8, b"other"), &kernel);
        assert!(state.tracked[&1].removed);
        state.lookups.insert(4, Answer::Pending);
        let mut reply = link(libc::RTM_NEWLINK, 0, 8, b"other");
        reply[8..12].copy_from_slice(&4u32.to_ne_bytes());
        state.receive(&reply, &SocketAddr::new(0, 0));
        assert!(matches!(state.lookups[&4], Answer::Found));
        let generation = state.generation;
        state.end_generation();
        assert!(state.generation > generation && state.tracked.is_empty());
    }
}
