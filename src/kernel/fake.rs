//! The in-memory kernel of the behavioural tests: a model of the kernel
//! facts the reconciler relies on, each rule marked with its K number, and
//! itself proved against the kernel by the conformance suite
//! (`docs/testing.md`). It is a namespace in memory, not a mock: tests
//! change the host through its controls and observe the operations the
//! daemon issued in [`FakeKernel::ops`].

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use nix::errno::Errno;

use super::{
    AddrInfo, Adopted, Family, HwAddr, Kernel, L2tpIfName, LinkInfo, Notice, Peer, Proof,
    Registration, SessionCreate, SessionInfo, SocketId, Subscription, TunnelInfo,
};

fn fail<T>(errno: Errno) -> io::Result<T> {
    Err(io::Error::from_raw_os_error(errno as i32))
}

struct FakeSocket {
    family: Family,
    tunnel_id: u32,
    peer_tunnel_id: u32,
    only_v6: bool,
    bound: Option<u32>,
    peer: Option<IpAddr>,
    source: Option<IpAddr>,
    // The descriptor handed out by `clone_fd` shares this inode.
    fd: Option<UnixStream>,
    lifetime: UnixStream,
    inode: u64,
}

impl FakeSocket {
    fn last_reference_closed(&self) -> bool {
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
        if self.fd.is_some() {
            return false;
        }
        let mut fds = [PollFd::new(self.lifetime.as_fd(), PollFlags::POLLHUP)];
        poll(&mut fds, PollTimeout::ZERO).unwrap();
        fds[0]
            .revents()
            .is_some_and(|flags| flags.contains(PollFlags::POLLHUP))
    }
}

struct FakeSession {
    info: SessionInfo,
    index: u32,
    gone_at_tick: bool,
}

struct FakeLink {
    info: LinkInfo,
    hwaddr: Option<HwAddr>,
    l2tpeth: bool,
    session: Option<(u32, u32)>,
    dropped: u64,
}

struct Tracked {
    index: u32,
    generation: u64,
    removed: bool,
}

/// A notification queue with the kernel's overflow behaviour (K29):
/// a message that does not fit is dropped and the next receive reports
/// the loss once, ahead of what is still queued.
#[derive(Default)]
struct Queue {
    items: VecDeque<Notice>,
    capacity: usize,
    overflowed: bool,
    waker: Option<Waker>,
}

impl Queue {
    fn push(&mut self, notice: Notice) {
        if self.items.len() >= self.capacity {
            self.overflowed = true;
        } else {
            self.items.push_back(notice);
        }
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }

    fn pop(&mut self) -> Option<Notice> {
        if std::mem::take(&mut self.overflowed) {
            return Some(Notice::Loss);
        }
        self.items.pop_front()
    }
}

struct Reader(Arc<Mutex<Queue>>);

impl Subscription for Reader {
    fn poll_notice(&mut self, cx: &mut Context<'_>) -> Poll<Notice> {
        let mut queue = self.0.lock().unwrap();
        match queue.pop() {
            Some(notice) => Poll::Ready(notice),
            None => {
                queue.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

/// The fake kernel. Construct with [`FakeKernel::new`], change the host
/// with its controls, hand it to the reconciler as a [`Kernel`].
pub struct FakeKernel {
    base: Instant,
    elapsed: Duration,
    seed: u64,
    next_socket: u64,
    sockets: BTreeMap<SocketId, FakeSocket>,
    // tunnel id -> its socket, `None` once the socket closed and the
    // deletion is queued (K17)
    tunnels: BTreeMap<u32, Option<SocketId>>,
    closed_since: BTreeMap<u32, Instant>,
    sessions: BTreeMap<(u32, u32), FakeSession>,
    links: BTreeMap<u32, FakeLink>,
    next_index: u32,
    addrs: Vec<AddrInfo>,
    refused: BTreeMap<IpAddr, Errno>,
    generation: u64,
    incarnation: u64,
    tracked: BTreeMap<u64, Tracked>,
    monitor: Arc<Mutex<Queue>>,
    l2tp: Arc<Mutex<Queue>>,
    failures: Vec<(&'static str, Errno)>,
    ops: Vec<String>,
    /// `AF_INET6` L2TP/IP sockets exist (K4, T4).
    pub inet6: bool,
    /// `net.ipv6.bindv6only` (K23).
    pub bindv6only: bool,
    /// A failure of the IPV6_V6ONLY read-back, for trust-boundary tests.
    pub only_v6_error: Option<Errno>,
    /// The daemon holds `CAP_NET_RAW` (K22). Off by default, so that a
    /// binding set on a bound socket fails as a daemon defect would.
    pub net_raw: bool,
    /// Session deletion waits for the next [`tick`](Self::tick), as from
    /// 6.12 (K18); immediate otherwise.
    pub async_session_delete: bool,
    /// Delay after the last descriptor closes before tunnel cleanup (K17).
    pub tunnel_delete_delay: Duration,
}

impl FakeKernel {
    /// An empty namespace, its random source seeded with `seed` (S4).
    pub fn new(seed: u64) -> Self {
        let queue = || {
            Arc::new(Mutex::new(Queue {
                capacity: 1 << 16,
                ..Queue::default()
            }))
        };
        FakeKernel {
            base: Instant::now(),
            elapsed: Duration::ZERO,
            seed: seed | 1,
            next_socket: 1,
            sockets: BTreeMap::new(),
            tunnels: BTreeMap::new(),
            closed_since: BTreeMap::new(),
            sessions: BTreeMap::new(),
            links: BTreeMap::new(),
            next_index: 1,
            addrs: Vec::new(),
            refused: BTreeMap::new(),
            generation: 1,
            incarnation: 0,
            tracked: BTreeMap::new(),
            monitor: queue(),
            l2tp: queue(),
            failures: Vec::new(),
            ops: Vec::new(),
            inet6: true,
            bindv6only: false,
            only_v6_error: None,
            net_raw: false,
            async_session_delete: true,
            tunnel_delete_delay: Duration::ZERO,
        }
    }

    fn next_random(&mut self) -> u64 {
        // xorshift64
        self.seed ^= self.seed << 13;
        self.seed ^= self.seed >> 7;
        self.seed ^= self.seed << 17;
        self.seed
    }

    fn injected(&mut self, op: &'static str) -> io::Result<()> {
        match self.failures.iter().position(|(o, _)| *o == op) {
            Some(i) => fail(self.failures.remove(i).1),
            None => Ok(()),
        }
    }

    fn by_name(&self, name: &L2tpIfName) -> Option<u32> {
        self.links
            .values()
            .find(|l| l.info.name == *name)
            .map(|l| l.info.index)
    }

    fn socket(&mut self, s: SocketId) -> io::Result<&mut FakeSocket> {
        self.sockets
            .get_mut(&s)
            .filter(|s| s.fd.is_some())
            .ok_or(io::Error::from_raw_os_error(Errno::EBADF as i32))
    }

    fn notify_link(&mut self, index: u32, removed: bool) {
        let info = self.links[&index].info.clone();
        self.monitor.lock().unwrap().push(if removed {
            Notice::LinkDel(info)
        } else {
            Notice::LinkNew(info)
        });
    }

    fn remove_session(&mut self, key: (u32, u32)) {
        if let Some(session) = self.sessions.remove(&key)
            && self
                .links
                .get(&session.index)
                .is_some_and(|l| l.session == Some(key))
        {
            self.unregister(session.index);
        }
    }

    fn unregister(&mut self, index: u32) {
        if self.links.contains_key(&index) {
            self.notify_link(index, true);
            self.links.remove(&index);
            self.addrs.retain(|a| a.index != index);
        }
        for tracked in self.tracked.values_mut() {
            if tracked.index == index {
                tracked.removed = true;
            }
        }
    }

    // ---- Controls: the host changes a test makes ----

    /// Advances the monotonic clock (M14).
    pub fn advance(&mut self, by: Duration) {
        self.elapsed += by;
    }

    /// Runs the kernel's queued work: deletions of tunnels whose socket
    /// closed, with every session on them (K17), and session deletions
    /// (K18).
    pub fn tick(&mut self) {
        let closed: Vec<u32> = self
            .tunnels
            .iter()
            .filter(|(tid, _)| {
                let sockets: Vec<_> = self
                    .sockets
                    .values()
                    .filter(|s| s.tunnel_id == **tid)
                    .collect();
                !sockets.is_empty() && sockets.iter().all(|s| s.last_reference_closed())
            })
            .map(|(id, _)| *id)
            .collect();
        for id in closed {
            let now = self.now();
            let closed = self.closed_since.entry(id).or_insert(now);
            if now.duration_since(*closed) < self.tunnel_delete_delay {
                continue;
            }
            let keys: Vec<_> = self
                .sessions
                .range((id, 0)..=(id, u32::MAX))
                .map(|(k, _)| *k)
                .collect();
            keys.into_iter().for_each(|k| self.remove_session(k));
            self.tunnels.remove(&id);
            self.closed_since.remove(&id);
            self.sockets.retain(|_, s| s.tunnel_id != id);
        }
        let doomed: Vec<_> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.gone_at_tick)
            .map(|(k, _)| *k)
            .collect();
        doomed.into_iter().for_each(|k| self.remove_session(k));
    }

    /// Adds a device and returns its index; indexes are allocated
    /// cyclically and never reused before they wrap.
    pub fn add_link(&mut self, name: &str, vrf: bool) -> u32 {
        let index = self.next_index;
        self.next_index += 1;
        self.add_link_at(index, name, vrf)
    }

    /// Adds a device under a given index, as a device moved in from
    /// another namespace keeps its index when it is free (S19).
    pub fn add_link_at(&mut self, index: u32, name: &str, vrf: bool) -> u32 {
        let name = L2tpIfName::new(name.as_bytes()).unwrap();
        let hwaddr = (!vrf).then(|| HwAddr::new([0x02, 0, 0x5e, 0, 0x53, index as u8]).unwrap());
        self.links.insert(
            index,
            FakeLink {
                info: LinkInfo {
                    index,
                    name,
                    up: false,
                    vrf,
                    master: None,
                },
                hwaddr,
                l2tpeth: false,
                session: None,
                dropped: 0,
            },
        );
        self.notify_link(index, false);
        index
    }

    /// Removes a device, or moves it to another namespace: either way it
    /// leaves this one (S19); a session device's session stays.
    pub fn remove_link(&mut self, index: u32) {
        self.unregister(index);
    }

    /// Renames a device, as another manager would.
    pub fn rename_link(&mut self, index: u32, name: &str) {
        self.links.get_mut(&index).unwrap().info.name = L2tpIfName::new(name.as_bytes()).unwrap();
        self.notify_link(index, false);
    }

    /// Brings a device up or down.
    pub fn set_up(&mut self, index: u32, up: bool) {
        self.links.get_mut(&index).unwrap().info.up = up;
        self.notify_link(index, false);
    }

    /// Sets a device's controller.
    pub fn set_master(&mut self, index: u32, master: Option<u32>) {
        self.links.get_mut(&index).unwrap().info.master = master;
        self.notify_link(index, false);
    }

    /// Sets a hardware address, as another manager would.
    pub fn set_link_hwaddr(&mut self, index: u32, addr: HwAddr) {
        self.links.get_mut(&index).unwrap().hwaddr = Some(addr);
        self.notify_link(index, false);
    }

    /// Makes a fixture device report no Ethernet address (V12).
    pub fn clear_link_hwaddr(&mut self, index: u32) {
        self.links.get_mut(&index).unwrap().hwaddr = None;
    }

    /// Adds an address to a device.
    pub fn add_addr(&mut self, index: u32, addr: IpAddr) {
        let info = AddrInfo { index, addr };
        self.addrs.push(info.clone());
        self.monitor.lock().unwrap().push(Notice::AddrNew(info));
    }

    /// Removes an address from a device.
    pub fn del_addr(&mut self, index: u32, addr: IpAddr) {
        let info = AddrInfo { index, addr };
        self.addrs.retain(|a| *a != info);
        self.monitor.lock().unwrap().push(Notice::AddrDel(info));
    }

    /// Makes connects to `peer` fail with `errno`, as a route of K26
    /// would; `None` makes the peer reachable again.
    pub fn refuse(&mut self, peer: IpAddr, errno: Option<Errno>) {
        match errno {
            Some(errno) => self.refused.insert(peer, errno),
            None => self.refused.remove(&peer),
        };
    }

    /// Makes the next call of the operation named `op` (the first word
    /// of its [`ops`](Self::ops) entry, or `scan`, `tunnel`, `session`,
    /// `link`, `dump`) fail with `errno`.
    pub fn fail_next(&mut self, op: &'static str, errno: Errno) {
        self.failures.push((op, errno));
    }

    /// An operator's `ip l2tp del session`: commanded over netlink, so
    /// announced (K41).
    pub fn operator_delete_session(&mut self, tunnel_id: u32, session_id: u32) {
        self.netlink_delete((tunnel_id, session_id));
    }

    /// Replaces a kernel tunnel behind the daemon's socket (unsupported,
    /// T9). The replacement's distinct socket must survive local cleanup.
    pub fn operator_replace_tunnel(&mut self, tunnel_id: u32, peer: u32) -> SocketId {
        let sessions: Vec<_> = self
            .sessions
            .keys()
            .filter(|(tid, _)| *tid == tunnel_id)
            .copied()
            .collect();
        for key in sessions {
            self.remove_session(key);
        }
        let socket = self.create_socket(Family::V6, u32::MAX, peer).unwrap();
        self.sockets.get_mut(&socket).unwrap().tunnel_id = tunnel_id;
        self.tunnels.insert(tunnel_id, Some(socket));
        self.l2tp
            .lock()
            .unwrap()
            .push(Notice::TunnelDeleted { tunnel_id });
        socket
    }

    /// A foreign session, created by someone else under `ifname`.
    pub fn foreign_session(&mut self, info: SessionInfo) -> u32 {
        let index = self.add_link(&info.ifname.unwrap().to_string_lossy(), false);
        self.links.get_mut(&index).unwrap().l2tpeth = true;
        self.links.get_mut(&index).unwrap().session = Some((info.tunnel_id, info.session_id));
        self.sessions.insert(
            (info.tunnel_id, info.session_id),
            FakeSession {
                info,
                index,
                gone_at_tick: false,
            },
        );
        index
    }

    /// Ends the lifetime subscription's generation, as an overflow would
    /// (E20, M18).
    pub fn lose_lifetime(&mut self) {
        self.generation += 1;
        self.tracked.clear();
    }

    /// Sets the event monitor's queue capacity (E20).
    pub fn set_monitor_capacity(&mut self, capacity: usize) {
        self.monitor.lock().unwrap().capacity = capacity;
    }

    /// Sets the L2TP event queue's capacity (E20, E21).
    pub fn set_l2tp_capacity(&mut self, capacity: usize) {
        self.l2tp.lock().unwrap().capacity = capacity;
    }

    /// Takes every queued event-monitor notice.
    pub fn take_monitor(&mut self) -> Vec<Notice> {
        std::iter::from_fn(|| self.monitor.lock().unwrap().pop()).collect()
    }

    /// Takes every queued `l2tp` group notice.
    pub fn take_l2tp(&mut self) -> Vec<Notice> {
        std::iter::from_fn(|| self.l2tp.lock().unwrap().pop()).collect()
    }

    // ---- Observations ----

    /// Every mutating operation the daemon issued, in order.
    pub fn ops(&self) -> &[String] {
        &self.ops
    }

    /// Forgets the recorded operations.
    pub fn clear_ops(&mut self) {
        self.ops.clear();
    }

    /// Whether a frame of the tunnel's sessions would leave the host: only
    /// when its socket is connected (K5).
    pub fn transmits(&self, tunnel_id: u32) -> bool {
        let socket = match self.tunnels.get(&tunnel_id) {
            Some(Some(id)) => self.sockets.get(id),
            Some(None) => self
                .sockets
                .values()
                .rev()
                .find(|s| s.tunnel_id == tunnel_id),
            None => None,
        };
        socket.is_some_and(|s| s.peer.is_some() && !s.last_reference_closed())
    }

    /// Emits one fixture frame, counting disconnected-session drops (K5).
    pub fn send_frame(&mut self, index: u32) {
        let tid = self.links[&index].session.expect("a session device").0;
        if !self.transmits(tid) {
            self.links.get_mut(&index).unwrap().dropped += 1;
        }
    }

    /// Frames dropped at a fixture session device (K5).
    pub fn tx_drops(&self, index: u32) -> u64 {
        self.links[&index].dropped
    }

    /// A socket's peer and source, `None` while disconnected.
    pub fn connection(&self, socket: SocketId) -> Option<(IpAddr, IpAddr)> {
        let s = self.sockets.get(&socket)?;
        Some((s.peer?, s.source?))
    }

    /// A socket's device binding.
    pub fn binding(&self, socket: SocketId) -> Option<u32> {
        self.sockets.get(&socket)?.bound
    }

    /// The socket a registered tunnel lives on.
    pub fn tunnel_socket(&self, tunnel_id: u32) -> Option<SocketId> {
        *self.tunnels.get(&tunnel_id)?
    }

    /// A device by index.
    pub fn link(&self, index: u32) -> Option<&LinkInfo> {
        self.links.get(&index).map(|l| &l.info)
    }

    /// A device's hardware address.
    pub fn hwaddr(&self, index: u32) -> Option<HwAddr> {
        self.links.get(&index)?.hwaddr
    }

    /// The device index of a session.
    pub fn session_index(&self, tunnel_id: u32, session_id: u32) -> Option<u32> {
        Some(self.sessions.get(&(tunnel_id, session_id))?.index)
    }

    /// The number of open sockets.
    pub fn open_sockets(&self) -> usize {
        self.sockets.values().filter(|s| s.fd.is_some()).count()
    }

    fn netlink_delete(&mut self, key: (u32, u32)) {
        // kernel: the announcement precedes the deletion (K41)
        self.l2tp.lock().unwrap().push(Notice::SessionDeleted {
            tunnel_id: key.0,
            session_id: key.1,
        });
        if self.async_session_delete {
            self.sessions.get_mut(&key).unwrap().gone_at_tick = true;
        } else {
            self.remove_session(key);
        }
    }

    // The source the kernel selects for `peer` in the socket's L3 domain
    // (K28, K34): an address of the peer's family on the bound device or,
    // for a VRF, on it or its members; anywhere outside VRFs if unbound.
    fn select_source(&self, bound: Option<u32>, peer: IpAddr) -> Option<IpAddr> {
        let vrf_of = |index: u32| {
            let link = &self.links[&index].info;
            if link.vrf {
                Some(index)
            } else {
                link.master
                    .filter(|m| self.links.get(m).is_some_and(|l| l.info.vrf))
            }
        };
        let domain = bound.and_then(vrf_of);
        let in_domain = |a: &&AddrInfo| match (bound, domain) {
            (_, Some(vrf)) => {
                a.index == vrf
                    || self
                        .links
                        .get(&a.index)
                        .is_some_and(|l| l.info.master == Some(vrf))
            }
            (Some(device), None) => a.index == device,
            (None, None) => self.links.contains_key(&a.index) && vrf_of(a.index).is_none(),
        };
        let link_local = |a: &IpAddr| matches!(a, IpAddr::V6(v6) if v6.is_unicast_link_local());
        self.addrs
            .iter()
            .filter(in_domain)
            .filter(|a| a.addr.is_ipv4() == peer.is_ipv4())
            .min_by_key(|a| link_local(&a.addr) != link_local(&peer))
            .map(|a| a.addr)
    }
}

impl Kernel for FakeKernel {
    fn now(&self) -> Instant {
        self.base + self.elapsed
    }

    fn random(&mut self) -> [u8; 3] {
        let [a, b, c, ..] = self.next_random().to_le_bytes();
        [a, b, c]
    }

    fn create_socket(
        &mut self,
        family: Family,
        tunnel_id: u32,
        peer_tunnel_id: u32,
    ) -> io::Result<SocketId> {
        self.injected("socket")?;
        // kernel: no AF_INET6 L2TP/IP sockets without IPv6 (K4, T4)
        if family == Family::V6 && !self.inet6 {
            return fail(Errno::EAFNOSUPPORT);
        }
        // kernel: a bound connection id is refused (K19, T7)
        if self.sockets.values().any(|s| {
            s.tunnel_id == tunnel_id && (s.fd.is_some() || self.tunnels.contains_key(&tunnel_id))
        }) {
            return fail(Errno::EADDRINUSE);
        }
        let id = SocketId(self.next_socket);
        self.next_socket += 1;
        let (fd, lifetime) = UnixStream::pair()?;
        let inode = std::fs::File::from(fd.as_fd().try_clone_to_owned()?)
            .metadata()?
            .ino();
        self.sockets.insert(
            id,
            FakeSocket {
                family,
                tunnel_id,
                peer_tunnel_id,
                // kernel: fixed at creation from bindv6only (K23)
                only_v6: family == Family::V6 && self.bindv6only,
                bound: None,
                peer: None,
                source: None,
                fd: Some(fd),
                lifetime,
                inode,
            },
        );
        self.ops
            .push(format!("socket {} {family} {tunnel_id}", id.0));
        Ok(id)
    }

    fn only_v6(&self, socket: SocketId) -> io::Result<bool> {
        let s = self
            .sockets
            .get(&socket)
            .ok_or(io::Error::from_raw_os_error(Errno::EBADF as i32))?;
        if s.family == Family::V4 {
            return fail(Errno::ENOPROTOOPT);
        }
        if let Some(error) = self.only_v6_error {
            return fail(error);
        }
        Ok(s.only_v6)
    }

    fn scratch_only_v6(&mut self) -> io::Result<bool> {
        if !self.inet6 {
            return fail(Errno::EAFNOSUPPORT);
        }
        Ok(self.bindv6only)
    }

    fn bind_index(&mut self, socket: SocketId, index: u32) -> io::Result<()> {
        self.injected("bind")?;
        let net_raw = self.net_raw;
        let present = self.links.contains_key(&index);
        let s = self.socket(socket)?;
        // kernel: replacing a binding needs CAP_NET_RAW (K22)
        if s.bound.is_some() && !net_raw {
            return fail(Errno::EPERM);
        }
        if !present {
            return fail(Errno::ENODEV);
        }
        s.bound = Some(index);
        self.ops.push(format!("bind {} {index}", socket.0));
        Ok(())
    }

    fn connect(&mut self, socket: SocketId, peer: &Peer) -> io::Result<IpAddr> {
        // An attempt is an operation, whatever its outcome.
        self.ops
            .push(format!("connect {} {}", socket.0, peer.addr.to_canonical()));
        self.injected("connect")?;
        let zone = peer.zone.as_ref().map(|z| self.by_name(z));
        let s = self
            .sockets
            .get(&socket)
            .ok_or(io::Error::from_raw_os_error(Errno::EBADF as i32))?;
        let (family, only_v6, connected, mut bound, previous) =
            (s.family, s.only_v6, s.peer, s.bound, s.source);
        let addr = peer.addr.to_canonical();
        if family == Family::V4 && addr.is_ipv6() {
            return fail(Errno::EAFNOSUPPORT);
        }
        // kernel: an IPv6-only socket refuses a mapped peer (K23)
        if only_v6 && addr.is_ipv4() {
            return fail(Errno::ENETUNREACH);
        }
        // kernel: a mapped-to-IPv6 connect without a disconnect (K24)
        if connected.is_some_and(|p| p.is_ipv4()) && addr.is_ipv6() {
            return fail(Errno::EAFNOSUPPORT);
        }
        if let Some(index) = bound
            && !self.links.contains_key(&index)
        {
            return fail(Errno::ENODEV);
        }
        if matches!(addr, IpAddr::V6(v6) if v6.is_unicast_link_local()) {
            match zone {
                // kernel: a link-local peer needs a scope or a binding (K26)
                None if bound.is_none() => return fail(Errno::EINVAL),
                None => {}
                Some(None) => return fail(Errno::ENODEV),
                // kernel: the scope must be the bound device or a member
                // of the bound VRF, and becomes the binding (K27)
                Some(Some(index)) => {
                    if bound
                        .is_some_and(|b| b != index && self.links[&index].info.master != Some(b))
                    {
                        return fail(Errno::EINVAL);
                    }
                    bound = Some(index);
                }
            }
        }
        if let Some(errno) = self.refused.get(&addr) {
            return fail(*errno);
        }
        // kernel: a connected socket keeps its source (K24)
        let source = match previous.filter(|_| connected.is_some()) {
            Some(source) => source,
            None => match self.select_source(bound, addr) {
                Some(source) => source,
                // kernel: IPv4 connects with 0.0.0.0, IPv6 fails (K34)
                None if addr.is_ipv4() => Ipv4Addr::UNSPECIFIED.into(),
                None => return fail(Errno::EADDRNOTAVAIL),
            },
        };
        let mapped = |a: IpAddr| match (family, a) {
            (Family::V6, IpAddr::V4(v4)) => IpAddr::V6(v4.to_ipv6_mapped()),
            _ => a,
        };
        let s = self.socket(socket)?;
        s.peer = Some(addr);
        s.source = Some(source);
        s.bound = bound;
        Ok(mapped(source))
    }

    fn disconnect(&mut self, socket: SocketId) -> io::Result<()> {
        self.injected("disconnect")?;
        let s = self.socket(socket)?;
        // kernel: clears the peer, the source and the binding (K22, K24)
        s.peer = None;
        s.source = None;
        s.bound = None;
        self.ops.push(format!("disconnect {}", socket.0));
        Ok(())
    }

    fn close(&mut self, socket: SocketId) {
        let now = self.now();
        if let Some(s) = self.sockets.get_mut(&socket) {
            if s.fd.take().is_none() {
                return;
            }
            // kernel: the tunnel's deletion is queued (K17)
            if let Some(entry) = self.tunnels.get_mut(&s.tunnel_id)
                && *entry == Some(socket)
            {
                *entry = None;
                if s.last_reference_closed() {
                    self.closed_since.insert(s.tunnel_id, now);
                }
            }
            self.ops.push(format!("close {}", socket.0));
            if !self.tunnels.contains_key(&s.tunnel_id) {
                self.sockets.remove(&socket);
            }
        }
    }

    fn clone_fd(&self, socket: SocketId) -> io::Result<OwnedFd> {
        let s = self
            .sockets
            .get(&socket)
            .ok_or(io::Error::from_raw_os_error(Errno::EBADF as i32))?;
        s.fd.as_ref()
            .ok_or(io::Error::from_raw_os_error(Errno::EBADF as i32))?
            .as_fd()
            .try_clone_to_owned()
    }

    fn adopt(&mut self, fd: OwnedFd) -> io::Result<Adopted> {
        self.injected("adopt")?;
        let inode = std::fs::File::from(fd.try_clone()?).metadata()?.ino();
        let s = self
            .sockets
            .values()
            .find(|s| s.inode == inode)
            .ok_or(io::Error::from_raw_os_error(Errno::ENOTSOCK as i32))?;
        let (family, tunnel_id, peer_tunnel_id) = (s.family, s.tunnel_id, s.peer_tunnel_id);
        self.next_socket += 1;
        let socket = SocketId(self.next_socket);
        let adopted = FakeSocket {
            family,
            tunnel_id,
            peer_tunnel_id,
            only_v6: s.only_v6,
            bound: s.bound,
            peer: s.peer,
            source: s.source,
            fd: Some(UnixStream::from(fd)),
            lifetime: s.lifetime.try_clone()?,
            inode,
        };
        self.sockets.insert(socket, adopted);
        self.tunnels.insert(tunnel_id, Some(socket));
        Ok(Adopted {
            socket,
            family,
            tunnel_id,
            peer_tunnel_id,
        })
    }

    fn register_tunnel(
        &mut self,
        socket: SocketId,
        tunnel_id: u32,
        peer_tunnel_id: u32,
    ) -> io::Result<()> {
        self.injected("register")?;
        // kernel: a registered identifier is refused (K19)
        if self.tunnels.contains_key(&tunnel_id) {
            return fail(Errno::EEXIST);
        }
        // The kernel would take any socket; a mismatch is a daemon defect.
        let s = self.socket(socket)?;
        if s.tunnel_id != tunnel_id || s.peer_tunnel_id != peer_tunnel_id {
            return fail(Errno::EINVAL);
        }
        // kernel: no socket state is checked (K5)
        self.tunnels.insert(tunnel_id, Some(socket));
        self.ops.push(format!("register {tunnel_id}"));
        Ok(())
    }

    fn tunnel(&mut self, tunnel_id: u32) -> io::Result<Option<TunnelInfo>> {
        self.injected("tunnel")?;
        Ok(self.tunnels.get(&tunnel_id).map(|s| TunnelInfo {
            tunnel_id,
            peer_tunnel_id: s.map_or_else(
                || {
                    self.sockets
                        .values()
                        .find(|s| s.tunnel_id == tunnel_id)
                        .map_or(0, |s| s.peer_tunnel_id)
                },
                |s| self.sockets[&s].peer_tunnel_id,
            ),
        }))
    }

    fn create_session(&mut self, create: &SessionCreate) -> io::Result<Registration> {
        self.injected("create")?;
        if !self.tunnels.contains_key(&create.tunnel_id) {
            return fail(Errno::ENODEV);
        }
        // kernel: session ids are unique in the namespace for IP
        // encapsulation (K19)
        if self.sessions.keys().any(|(_, s)| *s == create.session_id) {
            return fail(Errno::EEXIST);
        }
        // kernel: a device that cannot be registered, no session (K20)
        if self.by_name(&create.ifname).is_some() {
            return fail(Errno::EEXIST);
        }
        let index = self.next_index;
        self.next_index += 1;
        let [a, b, c, d, e, ..] = self.next_random().to_le_bytes();
        // kernel: a random hardware address, the device down (K31)
        let hwaddr = HwAddr::new([(a & 0xfe) | 0x02, b, c, d, e, 1]).unwrap();
        self.links.insert(
            index,
            FakeLink {
                info: LinkInfo {
                    index,
                    name: create.ifname,
                    up: false,
                    vrf: false,
                    master: None,
                },
                hwaddr: Some(hwaddr),
                l2tpeth: true,
                session: Some((create.tunnel_id, create.session_id)),
                dropped: 0,
            },
        );
        self.notify_link(index, false);
        self.sessions.insert(
            (create.tunnel_id, create.session_id),
            FakeSession {
                // kernel: the creation name is stored once (K16)
                info: SessionInfo {
                    tunnel_id: create.tunnel_id,
                    session_id: create.session_id,
                    peer_session_id: create.peer_session_id,
                    cookie: create.cookie.into(),
                    peer_cookie: create.peer_cookie.into(),
                    ifname: Some(create.ifname),
                },
                index,
                gone_at_tick: false,
            },
        );
        self.incarnation += 1;
        self.tracked.insert(
            self.incarnation,
            Tracked {
                index,
                generation: self.generation,
                removed: false,
            },
        );
        self.ops.push(format!(
            "create {} {} {}",
            create.tunnel_id,
            create.session_id,
            create.ifname.to_string_lossy()
        ));
        Ok(Registration {
            index,
            generation: self.generation,
            incarnation: self.incarnation,
        })
    }

    fn session(&mut self, tunnel_id: u32, session_id: u32) -> io::Result<Option<SessionInfo>> {
        self.injected("session")?;
        Ok(self
            .sessions
            .get(&(tunnel_id, session_id))
            .map(|s| s.info.clone()))
    }

    fn scan_sessions(
        &mut self,
        tunnel_id: Option<u32>,
        visit: &mut dyn FnMut(&SessionInfo),
    ) -> io::Result<()> {
        self.injected("scan")?;
        self.sessions
            .values()
            .filter(|s| tunnel_id.is_none_or(|t| s.info.tunnel_id == t))
            .for_each(|s| visit(&s.info));
        Ok(())
    }

    fn delete_session(&mut self, tunnel_id: u32, session_id: u32) -> io::Result<()> {
        self.injected("delete")?;
        if !self.sessions.contains_key(&(tunnel_id, session_id)) {
            return fail(Errno::ENODEV);
        }
        self.ops.push(format!("delete {tunnel_id} {session_id}"));
        self.netlink_delete((tunnel_id, session_id));
        Ok(())
    }

    fn delete_session_by_name(&mut self, ifname: &L2tpIfName) -> io::Result<()> {
        self.injected("delete")?;
        // kernel: the first session whose stored name matches (K16)
        let key = self
            .sessions
            .iter()
            .find(|(_, s)| s.info.ifname == Some(*ifname))
            .map(|(k, _)| *k);
        let key = key.ok_or(io::Error::from_raw_os_error(Errno::ENODEV as i32))?;
        self.ops
            .push(format!("delete-name {}", ifname.to_string_lossy()));
        self.netlink_delete(key);
        Ok(())
    }

    fn prove(&mut self, registration: &Registration) -> Proof {
        match self.tracked.get(&registration.incarnation) {
            Some(t)
                if t.generation != self.generation
                    || registration.generation != self.generation =>
            {
                Proof::Lost
            }
            Some(t) if !t.removed && t.index == registration.index => Proof::Proved,
            Some(_) => Proof::Removed,
            None => Proof::Lost,
        }
    }

    fn release(&mut self, registration: &Registration) {
        self.tracked.remove(&registration.incarnation);
    }

    fn link_by_name(&mut self, name: &L2tpIfName) -> io::Result<Option<LinkInfo>> {
        self.injected("link")?;
        Ok(self.by_name(name).map(|i| self.links[&i].info.clone()))
    }

    fn rename(&mut self, index: u32, name: &L2tpIfName) -> io::Result<()> {
        self.injected("rename")?;
        if !self.links.contains_key(&index) {
            return fail(Errno::ENODEV);
        }
        if self.by_name(name).is_some_and(|i| i != index) {
            return fail(Errno::EEXIST);
        }
        // kernel: allowed while up (K31)
        self.links.get_mut(&index).unwrap().info.name = *name;
        self.notify_link(index, false);
        self.ops
            .push(format!("rename {index} {}", name.to_string_lossy()));
        Ok(())
    }

    fn set_hwaddr(&mut self, index: u32, addr: HwAddr) -> io::Result<()> {
        self.injected("hwaddr")?;
        let link = self
            .links
            .get_mut(&index)
            .ok_or(io::Error::from_raw_os_error(Errno::ENODEV as i32))?;
        // kernel: a change is refused while up on an l2tpeth device; the
        // same address is not a change (K31, dev_set_mac_address)
        if link.l2tpeth && link.info.up && link.hwaddr != Some(addr) {
            return fail(Errno::EBUSY);
        }
        link.hwaddr = Some(addr);
        self.notify_link(index, false);
        self.ops.push(format!("hwaddr {index} {addr}"));
        Ok(())
    }

    fn ether_addr(&mut self, index: u32) -> io::Result<Option<HwAddr>> {
        self.injected("link")?;
        match self.links.get(&index) {
            Some(link) => Ok(link.hwaddr),
            None => fail(Errno::ENODEV),
        }
    }

    fn dump_links(&mut self) -> io::Result<Vec<LinkInfo>> {
        self.injected("dump")?;
        Ok(self.links.values().map(|l| l.info.clone()).collect())
    }

    fn dump_addrs(&mut self) -> io::Result<Vec<AddrInfo>> {
        self.injected("dump")?;
        Ok(self.addrs.clone())
    }

    fn monitor(&mut self) -> io::Result<Box<dyn Subscription>> {
        Ok(Box::new(Reader(self.monitor.clone())))
    }

    fn l2tp_events(&mut self) -> io::Result<Box<dyn Subscription>> {
        Ok(Box::new(Reader(self.l2tp.clone())))
    }
}
