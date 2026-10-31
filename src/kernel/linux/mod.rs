//! The real kernel: tunnel sockets through `l2tp`, generic netlink and
//! rtnetlink requests through a bounded adapter over `netlink-sys`, and
//! the subscriptions on raw sockets. Every function cites the kernel fact
//! it relies on (`// kernel: ... (Kn)`).

mod bpf;
mod l2tp;
mod lifetime;
mod monitor;
mod request;
mod rtnl;
mod socket;

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Instant;

use nix::libc;

use self::l2tp::Genl;
use self::lifetime::Lifetime;
use self::request::{DEADLINE, errno};
use self::rtnl::Rtnl;
use self::socket::Tunnel;
use super::{
    AddrInfo, Adopted, Family, HwAddr, Kernel, L2tpIfName, LinkInfo, Peer, Proof, Registration,
    SessionCreate, SessionInfo, SocketId, Subscription, TunnelInfo,
};

/// The kernel of the daemon's network namespace (A5).
pub struct LinuxKernel {
    sockets: HashMap<SocketId, Tunnel>,
    next_socket: u64,
    genl: Genl,
    rtnl: Rtnl,
    lifetime: Lifetime,
}

impl LinuxKernel {
    // kernel: (K1, K7, K8, K21) net/netlink/genetlink.c:1446-1447 and
    // l2tp_netlink.c:620-626 (the family autoloads), the capability checks of
    // rtnetlink and the l2tp family come at the first request
    /// Opens the request sockets, resolves the `l2tp` family and starts
    /// the lifetime subscription; an error means the kernel cannot be used
    /// at all (L9).
    pub fn new() -> io::Result<Self> {
        Ok(LinuxKernel {
            sockets: HashMap::new(),
            next_socket: 0,
            genl: Genl::new()?,
            rtnl: Rtnl::new()?,
            lifetime: Lifetime::new()?,
        })
    }

    // kernel: net/l2tp/l2tp_ip.c:236-246 (K17)
    fn socket(&self, socket: SocketId) -> io::Result<&Tunnel> {
        self.sockets.get(&socket).ok_or_else(|| errno(libc::EBADF))
    }

    // kernel: net/l2tp/l2tp_ip.c:236-246 (K17, K37)
    fn hold(&mut self, tunnel: Tunnel) -> SocketId {
        self.next_socket += 1;
        let id = SocketId(self.next_socket);
        self.sockets.insert(id, tunnel);
        id
    }
}

impl Kernel for LinuxKernel {
    // kernel: clock_gettime(CLOCK_MONOTONIC), on which the waits for the
    // deferred deletions of K17 and K18 are timed (M14)
    fn now(&self) -> Instant {
        Instant::now()
    }

    // kernel: drivers/char/random.c getrandom(2); OS entropy only, with errors returned (S4)
    fn random(&mut self) -> io::Result<[u8; 3]> {
        let mut bytes = [0; 3];
        getrandom::fill(&mut bytes)
            .map_err(|error| errno(error.raw_os_error().unwrap_or(libc::EIO)))?;
        Ok(bytes)
    }

    // kernel: (K2, K4, K19) net/l2tp/l2tp_ip.c l2tp_ip_bind, l2tp_ip6.c
    // l2tp_ip6_bind; net/ipv6/af_inet6.c:164-173
    fn create_socket(
        &mut self,
        family: Family,
        tunnel_id: u32,
        peer_tunnel_id: u32,
    ) -> io::Result<SocketId> {
        let tunnel = Tunnel::create(family, tunnel_id, peer_tunnel_id)?;
        Ok(self.hold(tunnel))
    }

    // kernel: net/ipv6/ipv6_sockglue.c:1212-1214 (K23)
    fn only_v6(&self, socket: SocketId) -> io::Result<bool> {
        self.socket(socket)?.only_v6()
    }

    // kernel: net/ipv6/af_inet6.c:228 (K11, K23)
    fn scratch_only_v6(&mut self) -> io::Result<bool> {
        socket::scratch_only_v6()
    }

    // kernel: net/core/sock.c:627-655, 671-717 (K22, K39)
    fn bind_index(&mut self, socket: SocketId, index: u32) -> io::Result<()> {
        self.socket(socket)?.bind_index(index)
    }

    // kernel: net/ipv6/datagram.c:51, 206-238; net/ipv4/datagram.c:38-39 (K24, K26, K27, K34)
    fn connect(&mut self, socket: SocketId, peer: &Peer) -> io::Result<IpAddr> {
        self.socket(socket)?.connect(peer)
    }

    // kernel: net/ipv4/udp.c:1998-2013 (K22, K25)
    fn disconnect(&mut self, socket: SocketId) -> io::Result<()> {
        self.socket(socket)?.disconnect()
    }

    // kernel: (K17) net/l2tp/l2tp_ip.c:236-246, l2tp_core.c:1574-1581 (deletion
    // queued at the last close)
    fn close(&mut self, socket: SocketId) {
        self.sockets.remove(&socket);
        // Geometric shrinking bounds storage by survivors without copying on every close (G23).
        if self.sockets.capacity() > self.sockets.len().saturating_mul(4).max(16) {
            self.sockets.shrink_to(self.sockets.len());
        }
    }

    // kernel: fs/fcntl.c F_DUPFD_CLOEXEC; a duplicate keeps the tunnel (K37)
    fn clone_fd(&self, socket: SocketId) -> io::Result<OwnedFd> {
        self.socket(socket)?.socket.try_clone_fd()
    }

    // kernel: (K25, K37) net/l2tp/l2tp_ip.c:236-246; the peer id of an IPv4
    // socket is reported only by the tunnel record, l2tp_netlink.c
    // l2tp_nl_tunnel_send
    fn adopt(&mut self, fd: OwnedFd) -> io::Result<Adopted> {
        let genl = &mut self.genl;
        let (tunnel, tunnel_id, peer_tunnel_id) = socket::adopt(fd, |id| {
            let info = genl.tunnel(id)?.ok_or_else(|| errno(libc::ENODEV))?;
            Ok(info.peer_tunnel_id)
        })?;
        let family = tunnel.family;
        Ok(Adopted {
            socket: self.hold(tunnel),
            family,
            tunnel_id,
            peer_tunnel_id,
        })
    }

    // kernel: (K5, K19) net/l2tp/l2tp_netlink.c l2tp_nl_cmd_tunnel_create,
    // l2tp_core.c:1467-1503
    fn register_tunnel(
        &mut self,
        socket: SocketId,
        tunnel_id: u32,
        peer_tunnel_id: u32,
    ) -> io::Result<()> {
        let fd = self.socket(socket)?.socket.as_raw_fd();
        self.genl.register_tunnel(fd, tunnel_id, peer_tunnel_id)
    }

    // kernel: net/l2tp/l2tp_netlink.c l2tp_nl_cmd_tunnel_get (472) (K25)
    fn tunnel(&mut self, tunnel_id: u32) -> io::Result<Option<TunnelInfo>> {
        self.genl.tunnel(tunnel_id)
    }

    // kernel: (K16, K19, K20) net/l2tp/l2tp_eth.c:249-310 (the device registers
    // under the name and broadcasts before the name is stored; a taken name
    // creates nothing), l2tp_core.c:342-384 (EEXIST)
    /// The capture is armed before the request (S8); a creation whose
    /// broadcast is not seen within the deadline is uncertain (`ETIMEDOUT`).
    fn create_session(&mut self, create: &SessionCreate) -> io::Result<Registration> {
        let deadline = Instant::now() + DEADLINE;
        let generation = self.lifetime.arm(&create.ifname)?;
        match self.genl.create_session(create, deadline) {
            // A request that timed out may have created it: its broadcast says.
            Err(error) if error.raw_os_error() != Some(libc::ETIMEDOUT) => {
                self.lifetime.disarm(&create.ifname);
                Err(error)
            }
            _ => self.lifetime.capture(&create.ifname, generation, deadline),
        }
    }

    // kernel: net/l2tp/l2tp_netlink.c l2tp_nl_cmd_session_get (K16, K35)
    fn session(&mut self, tunnel_id: u32, session_id: u32) -> io::Result<Option<SessionInfo>> {
        self.genl.session(tunnel_id, session_id)
    }

    // kernel: net/l2tp/l2tp_netlink.c l2tp_nl_cmd_session_dump (K16)
    fn scan_sessions(
        &mut self,
        tunnel_id: Option<u32>,
        visit: &mut dyn FnMut(&SessionInfo),
    ) -> io::Result<()> {
        self.genl.scan_sessions(tunnel_id, visit)
    }

    // kernel: net/l2tp/l2tp_netlink.c l2tp_nl_cmd_session_delete (K18)
    fn delete_session(&mut self, tunnel_id: u32, session_id: u32) -> io::Result<()> {
        self.genl.delete_session(tunnel_id, session_id)
    }

    // kernel: net/l2tp/l2tp_netlink.c:55-57 (K16)
    fn delete_session_by_name(&mut self, ifname: &L2tpIfName) -> io::Result<()> {
        self.genl.delete_session_by_name(ifname)
    }

    // kernel: net/core/rtnetlink.c rtnl_getlink (K29)
    fn prove(&mut self, registration: &Registration) -> Proof {
        self.lifetime.prove(registration)
    }

    // kernel: net/core/dev.c unregister_netdevice (K29)
    fn release(&mut self, registration: &Registration) {
        self.lifetime.release(registration)
    }

    // kernel: (K9, K32) net/core/rtnetlink.c rtnl_getlink: ifi_index lookup.
    fn link_by_index(&mut self, index: u32) -> io::Result<Option<LinkInfo>> {
        self.rtnl.link_by_index(index)
    }

    // kernel: (K9, K32) net/core/rtnetlink.c rtnl_getlink: IFLA_IFNAME lookup.
    fn link_by_name(&mut self, name: &L2tpIfName) -> io::Result<Option<LinkInfo>> {
        self.rtnl.link_by_name(name)
    }

    // kernel: net/core/dev.c dev_change_name (K31, K32)
    fn rename(&mut self, index: u32, name: &L2tpIfName) -> io::Result<()> {
        self.rtnl.rename(index, name)
    }

    // kernel: net/l2tp/l2tp_eth.c:95-115 (K31)
    fn set_hwaddr(&mut self, index: u32, addr: HwAddr) -> io::Result<()> {
        self.rtnl.set_hwaddr(index, addr)
    }

    // kernel: net/core/rtnetlink.c rtnl_fill_ifinfo (IFLA_ADDRESS) (K31)
    fn ether_addr(&mut self, index: u32) -> io::Result<Option<HwAddr>> {
        self.rtnl.ether_addr(index)
    }

    // kernel: net/core/rtnetlink.c rtnl_dump_ifinfo (K7)
    fn dump_links(&mut self) -> io::Result<Vec<LinkInfo>> {
        self.rtnl.dump_links()
    }

    // kernel: net/core/rtnetlink.c rtnl_dump_all (K7)
    fn dump_addrs(&mut self) -> io::Result<Vec<AddrInfo>> {
        self.rtnl.dump_addrs()
    }

    // kernel: net/core/filter.c sk_attach_filter (K7, K10, K29)
    fn monitor(&mut self) -> io::Result<Box<dyn Subscription>> {
        Ok(Box::new(monitor::monitor()?))
    }

    // kernel: net/l2tp/l2tp_netlink.c:102-160, 664-665 (K41)
    fn l2tp_events(&mut self) -> io::Result<Box<dyn Subscription>> {
        Ok(Box::new(self.genl.events()?))
    }
}

#[cfg(test)]
mod resources_tests {
    use super::*;

    // kernel: net/l2tp/l2tp_ip6.c l2tp_ip6_bind and l2tp_ip6_close (K4, K17)
    /// spec: G23, M16
    #[test]
    #[ignore = "isolated network namespace with CAP_NET_ADMIN and L2TP modules"]
    fn socket_storage_follows_survivors_after_a_large_configuration() {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
        let mut kernel = LinuxKernel::new().unwrap();
        let sockets: Vec<_> = (1..=300)
            .map(|id| kernel.create_socket(Family::V6, id, id + 1000).unwrap())
            .collect();
        let survivor = kernel.socket(sockets[0]).unwrap().socket.as_raw_fd();
        for socket in sockets.iter().skip(1) {
            kernel.close(*socket);
            assert!(kernel.sockets.capacity() <= kernel.sockets.len().saturating_mul(4).max(16));
        }
        assert_eq!(
            kernel.socket(sockets[0]).unwrap().socket.as_raw_fd(),
            survivor
        );
        assert_eq!(
            kernel.socket(sockets[1]).err().unwrap().raw_os_error(),
            Some(libc::EBADF)
        );
        assert_eq!(kernel.sockets.len(), 1);
        assert!(
            kernel.sockets.capacity() <= 16,
            "retained {} slots for one tunnel",
            kernel.sockets.capacity()
        );
        kernel.close(sockets[0]);
        assert!(kernel.sockets.capacity() <= 16);
    }
}
