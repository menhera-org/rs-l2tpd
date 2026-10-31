//! Tunnel sockets: creation disconnected, binding by index, the reconnect
//! steps, the read-backs (spec T3–T6, T10, T21, T26, K22–K26), over
//! `l2tp::TunnelSocket`.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::sync::Once;

use l2tp::{IpEndpoint, PmtuDiscovery, TunnelId, TunnelSocket};
use nix::libc;
use socket2::{Domain, Protocol, SockRef, Type};

use super::request::errno;
use crate::kernel::{Family, Peer};

/// `IPPROTO_L2TP`.
const IPPROTO_L2TP: i32 = 115;

// kernel: (K24, K26) net/l2tp/l2tp_ip.c, l2tp_ip6.c connect and bind errors
// arrive as errno; the crate's own refusals map to the kernel's
/// The errno of an `l2tp` error: the kernel's, or the one the kernel would
/// give for what the crate refused before asking it.
pub(super) fn os(error: l2tp::Error) -> io::Error {
    if let Some(code) = error.raw_os_error() {
        return errno(code);
    }
    log::debug!("tunnel socket: {error}");
    errno(match error {
        l2tp::Error::AddressFamilyMismatch => libc::EAFNOSUPPORT,
        _ => libc::EINVAL,
    })
}

/// A tunnel socket and its family.
pub(super) struct Tunnel {
    pub socket: TunnelSocket,
    pub family: Family,
}

impl Tunnel {
    // kernel: (K2, K4, K19, K21, K44) net/l2tp/l2tp_ip.c l2tp_ip_bind, l2tp_ip6.c
    // l2tp_ip6_bind (the connection id bound on the unspecified address,
    // EADDRINUSE when taken); net/ipv6/af_inet6.c:164-173 (EAFNOSUPPORT,
    // EPROTONOSUPPORT); the socket is created SOCK_CLOEXEC
    // K44: net/ipv4/ip_sockglue.c IP_MTU_DISCOVER and net/ipv6/ipv6_sockglue.c
    // IPV6_MTU_DISCOVER/IPV6_DONTFRAG, applied before the first connect.
    /// A socket of `family` bound to the unspecified address with
    /// `tunnel_id`, unconnected (T1, T6).
    pub(super) fn create(family: Family, tunnel_id: u32, peer_tunnel_id: u32) -> io::Result<Self> {
        let local = match family {
            Family::V4 => IpEndpoint::V4(Ipv4Addr::UNSPECIFIED),
            _ => IpEndpoint::v6(Ipv6Addr::UNSPECIFIED),
        };
        let socket = TunnelSocket::ip_unconnected(
            &local,
            None,
            TunnelId(tunnel_id),
            TunnelId(peer_tunnel_id),
        )
        .map_err(os)?;
        static V4: Once = Once::new();
        static V6: Once = Once::new();
        static DONTFRAG: Once = Once::new();
        option_report(
            if family == Family::V4 { &V4 } else { &V6 },
            if family == Family::V4 {
                "IP_MTU_DISCOVER"
            } else {
                "IPV6_MTU_DISCOVER"
            },
            socket.set_pmtu_discovery(PmtuDiscovery::Dont).map_err(os),
        );
        if family == Family::V6 {
            use std::os::fd::AsFd;
            option_report(&V4, "IP_MTU_DISCOVER", ipv4_fragmentation(socket.as_fd()));
            option_report(
                &DONTFRAG,
                "IPV6_DONTFRAG",
                socket.set_ipv6_dontfrag(false).map_err(os),
            );
        }
        Ok(Tunnel { socket, family })
    }

    // kernel: (K11, K23) net/ipv6/af_inet6.c:228, ipv6_sockglue.c:1212-1214
    // (always readable)
    pub(super) fn only_v6(&self) -> io::Result<bool> {
        SockRef::from(&self.socket).only_v6()
    }

    // kernel: (K22, K39) net/core/sock.c:627-655 (CAP_NET_RAW only to replace a
    // binding), 671-717
    pub(super) fn bind_index(&self, index: u32) -> io::Result<()> {
        self.socket.bind_to_device_index(index).map_err(os)
    }

    // kernel: (K6, K23, K24, K26, K27, K28, K34) net/l2tp/l2tp_ip.c
    // l2tp_ip_connect, l2tp_ip6.c l2tp_ip6_connect; net/ipv4/datagram.c:38-39,
    // 64-65 and net/ipv6/datagram.c:51, 185-191, 206-238 (a mapped peer, the
    // scope binding the zone device, the source kept until a disconnect);
    // net/ipv4/devinet.c:1370-1376 (source 0.0.0.0 without an IPv4 address)
    /// Connects and reads back the source the kernel selected, unspecified
    /// included (T28).
    pub(super) fn connect(&self, peer: &Peer) -> io::Result<IpAddr> {
        let endpoint = match (self.family, peer.addr) {
            (Family::V4, IpAddr::V4(addr)) => IpEndpoint::V4(addr),
            (Family::V4, IpAddr::V6(_)) => return Err(errno(libc::EAFNOSUPPORT)),
            (_, IpAddr::V4(addr)) => IpEndpoint::v6(addr.to_ipv6_mapped()),
            (_, IpAddr::V6(addr)) => match peer.zone {
                Some(zone) => IpEndpoint::v6_scoped(addr, zone),
                None => IpEndpoint::v6(addr),
            },
        };
        self.socket.reconnect_ip(&endpoint).map_err(os)?;
        Ok(self.socket.local_addr_ip().map_err(os)?.ip())
    }

    // kernel: (K6, K22, K24, K25) net/ipv4/udp.c:1998-2013 __udp_disconnect
    // (peer, sources and binding cleared, sk_v6_daddr kept)
    pub(super) fn disconnect(&self) -> io::Result<()> {
        self.socket.disconnect().map_err(os)
    }
}

// kernel: (K4, K11, K23) net/ipv6/af_inet6.c:228 (IPV6_V6ONLY from bindv6only
// at creation), 164-173
/// Whether a new `AF_INET6` L2TP/IP socket would be IPv6-only (E25).
pub(super) fn scratch_only_v6() -> io::Result<bool> {
    let socket = socket2::Socket::new(
        Domain::IPV6,
        Type::DGRAM,
        Some(Protocol::from(IPPROTO_L2TP)),
    )?;
    socket.only_v6()
}

// kernel: (K37) net/l2tp/l2tp_ip.c:236-246 (the tunnel lives as long as a
// descriptor of its socket)
/// Takes over a handed-over socket; `peer_of` asks the kernel for the
/// peer tunnel id, which an IPv4 socket does not report (P14).
pub(super) fn adopt(
    fd: OwnedFd,
    peer_of: impl FnOnce(u32) -> io::Result<u32>,
) -> io::Result<(Tunnel, u32, u32)> {
    let family = match SockRef::from(&fd).domain()? {
        Domain::IPV4 => Family::V4,
        Domain::IPV6 => Family::V6,
        _ => return Err(errno(libc::EAFNOSUPPORT)),
    };
    let socket = TunnelSocket::from_fd(fd).map_err(os)?;
    // kernel: (K37) net/l2tp/l2tp_ip.c l2tp_ip_getname, l2tp_ip6.c
    // l2tp_ip6_getname (the bound connection id, read by from_fd)
    let tunnel_id = socket
        .tunnel_id()
        .map(|t| t.0)
        .ok_or_else(|| errno(libc::EPROTONOSUPPORT))?;
    let peer = peer_of(tunnel_id)?;
    let socket = TunnelSocket::from_fd_with_peer(socket.into_fd(), TunnelId(peer)).map_err(os)?;
    Ok((Tunnel { socket, family }, tunnel_id, peer))
}

// kernel: (K44) net/ipv6/ipv6_sockglue.c:934-935 delegates SOL_IP on a
// datagram socket to IPv4; the IPv4 mode also governs mapped peers.
#[allow(unsafe_code)]
fn ipv4_fragmentation(fd: BorrowedFd<'_>) -> io::Result<()> {
    let mode = libc::IP_PMTUDISC_DONT;
    // SAFETY: fd is borrowed and live, and the option reads a local integer
    // through its correctly sized pointer. No pointer or descriptor is retained.
    let result = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            (&mode as *const libc::c_int).cast(),
            std::mem::size_of_val(&mode) as libc::socklen_t,
        )
    };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// kernel: (K44) an option refusal leaves the socket usable with host defaults.
fn option_report(once: &Once, name: &str, result: io::Result<()>) {
    if let Err(error) = result {
        once.call_once(|| {
            log::error!("host refuses {name} required for tunnel fragmentation: {error}");
        });
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    // kernel: (K44) an option refusal preserves errno and leaves the descriptor live.
    #[test]
    fn ipv4_fragmentation_refusal_preserves_io_error_and_socket() {
        let (socket, _) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(
            ipv4_fragmentation(socket.as_fd())
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EOPNOTSUPP)
        );
        assert!(socket.peer_addr().is_ok());
    }
}
