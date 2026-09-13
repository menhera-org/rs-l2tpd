use crate::error::{Error, Result};

use futures_util::TryStreamExt;
use log::warn;
use rtnetlink::LinkUnspec;

use tokio::sync::RwLock;

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv6Addr},
    os::fd::AsRawFd,
    sync::Arc,
};

pub(crate) async fn rename_interface(old: &str, new: &str) -> Result<()> {
    let (connection, handle, _) = rtnetlink::new_connection()
        .map_err(|e| Error::Other(format!("failed to create netlink connection: {e}")))?;
    tokio::spawn(connection);

    let mut links = handle.link().get().match_name(old.to_string()).execute();
    let link = links
        .try_next()
        .await
        .map_err(|e| Error::Other(format!("failed to look up interface {old}: {e}")))?
        .ok_or_else(|| Error::Other(format!("interface not found: {old}")))?;

    handle
        .link()
        .set(
            LinkUnspec::new_with_index(link.header.index)
                .name(new.to_string())
                .build(),
        )
        .execute()
        .await
        .map_err(|e| Error::Other(format!("failed to rename interface {old} to {new}: {e}")))?;

    Ok(())
}

pub(crate) async fn interface_exists(if_name: &str) -> Result<bool> {
    Ok(interface_index(if_name).await?.is_some())
}

pub(crate) async fn interface_index(if_name: &str) -> Result<Option<u32>> {
    let (connection, handle, _) = rtnetlink::new_connection()
        .map_err(|e| Error::Other(format!("failed to create netlink connection: {e}")))?;
    tokio::spawn(connection);

    let mut links = handle
        .link()
        .get()
        .match_name(if_name.to_string())
        .execute();
    links
        .try_next()
        .await
        .map(|link| link.map(|link| link.header.index))
        .map_err(|e| Error::Other(format!("failed to look up interface {if_name}: {e}")))
}

pub(crate) fn to_ipv6_mapped(addr: IpAddr) -> Ipv6Addr {
    match addr {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

pub(crate) struct SessionState {
    pub(crate) interface_name: Arc<RwLock<String>>,
    // Keep session handle alive for the session lifecycle even when we don't call methods on it.
    #[allow(dead_code)]
    pub(crate) handle: Arc<l2tp::SessionHandle>,
}

pub(crate) struct TunnelState {
    pub(crate) remote_addr: Arc<RwLock<IpAddr>>,
    pub(crate) handle: l2tp::TunnelHandle,
    // Last successfully applied device, retained across disconnects for retries.
    // The write lock serializes binding and the entire reconnect sequence.
    bound_interface: RwLock<Option<l2tp::IfName>>,

    /// session_id to SessionState
    pub(crate) sessions: Arc<RwLock<BTreeMap<u32, SessionState>>>,
}

pub(crate) struct State {
    pub(crate) handle: l2tp::L2tpHandle,

    /// tunnel_id to TunnelState
    pub(crate) tunnels: Arc<RwLock<BTreeMap<u32, TunnelState>>>,
}

fn parse_if_name(if_name: Option<&str>) -> Result<Option<l2tp::IfName>> {
    if let Some(name) = if_name {
        return Ok(Some(l2tp::IfName::new(name).map_err(Error::L2tp)?));
    }
    Ok(None)
}

fn bind_tunnel_socket(tunnel: &TunnelState, if_name: &l2tp::IfName) -> Result<()> {
    let socket = tunnel
        .handle
        .socket()
        .ok_or_else(|| Error::Other("tunnel has no managed socket".to_string()))?;
    socket.bind_to_device(if_name).map_err(Error::L2tp)
}

fn verify_reconnected_endpoint(
    tunnel_id: u32,
    if_name: Option<&l2tp::IfName>,
    encapsulation: &l2tp::Encapsulation,
) -> Result<()> {
    let reason = match encapsulation {
        l2tp::Encapsulation::Ip { local, .. } => {
            let unspecified = match local {
                l2tp::IpEndpoint::V4(addr) => addr.is_unspecified(),
                l2tp::IpEndpoint::V6(addr) => addr.is_unspecified(),
            };
            if !unspecified {
                return Ok(());
            }
            "kernel reports an unspecified local endpoint after reconnect"
        }
        _ => "kernel reports unexpected encapsulation after IP reconnect",
    };
    let message = format!(
        "{reason} tunnel_id={tunnel_id} if_name={}",
        if_name.map(l2tp::IfName::as_str).unwrap_or("<unbound>")
    );
    warn!("{message}");
    Err(Error::Other(message))
}

fn remove_if_delete_succeeded<K: Ord, V>(
    map: &mut BTreeMap<K, V>,
    key: &K,
    delete_result: Result<()>,
) -> Result<Option<V>> {
    delete_result?;
    Ok(map.remove(key))
}

impl State {
    pub(crate) async fn new() -> Result<Self> {
        let handle = l2tp::L2tpHandle::new().await.map_err(Error::L2tp)?;
        let tunnels = Arc::new(RwLock::new(BTreeMap::new()));
        Ok(Self { handle, tunnels })
    }

    pub(crate) async fn has_tunnel(&self, tunnel_id: u32) -> bool {
        self.tunnels.read().await.contains_key(&tunnel_id)
    }

    pub(crate) async fn has_interface(if_name: &str) -> Result<bool> {
        interface_exists(if_name).await
    }

    pub(crate) async fn interface_index(if_name: &str) -> Result<Option<u32>> {
        interface_index(if_name).await
    }

    pub(crate) async fn add_tunnel(
        &self,
        tunnel_id: u32,
        peer_tunnel_id: u32,
        remote_addr: IpAddr,
        if_name: Option<&str>,
    ) -> Result<()> {
        if self.has_tunnel(tunnel_id).await {
            return Err(Error::Other("Duplicate tunnel_id".to_string()));
        }

        let if_name = parse_if_name(if_name)?;

        let local = l2tp::IpEndpoint::V6(Ipv6Addr::UNSPECIFIED);
        let remote = l2tp::IpEndpoint::V6(to_ipv6_mapped(remote_addr));

        let socket = l2tp::TunnelSocket::ip(&local, &remote, if_name.as_ref(), tunnel_id)
            .map_err(Error::L2tp)?;

        let config = l2tp::TunnelConfig::new(
            l2tp::TunnelId(tunnel_id),
            l2tp::TunnelId(peer_tunnel_id),
            l2tp::Encapsulation::Ip { local, remote },
        )
        .map_err(Error::L2tp)?;

        let mut handle = self
            .handle
            .create_tunnel(config, socket)
            .await
            .map_err(Error::L2tp)?;

        handle.set_auto_delete(false);

        let tunnel = TunnelState {
            remote_addr: Arc::new(RwLock::new(remote_addr)),
            handle,
            bound_interface: RwLock::new(if_name),
            sessions: Arc::new(RwLock::new(BTreeMap::new())),
        };

        self.tunnels.write().await.insert(tunnel_id, tunnel);

        Ok(())
    }

    pub(crate) async fn modify_tunnel(&self, tunnel_id: u32, remote_addr: IpAddr) -> Result<()> {
        let mut tunnels = self.tunnels.write().await;
        let tunnel = if let Some(t) = tunnels.get_mut(&tunnel_id) {
            t
        } else {
            return Err(Error::Other("tunnel not found".to_string()));
        };

        if *tunnel.remote_addr.read().await == remote_addr {
            return Ok(());
        }

        let new_remote = l2tp::IpEndpoint::V6(to_ipv6_mapped(remote_addr));
        tunnel
            .handle
            .reconnect_ip(&new_remote)
            .map_err(Error::L2tp)?;

        *tunnel.remote_addr.write().await = remote_addr;

        Ok(())
    }

    pub(crate) async fn reconnect_tunnel(&self, tunnel_id: u32) -> Result<()> {
        let tunnels = self.tunnels.read().await;
        let tunnel = tunnels
            .get(&tunnel_id)
            .ok_or_else(|| Error::Other("tunnel not found".to_string()))?;
        let bound_interface = tunnel.bound_interface.write().await;
        let socket = tunnel
            .handle
            .socket()
            .ok_or_else(|| Error::Other("tunnel has no managed socket".to_string()))?;

        // Disconnect to clear a stale source address and force source selection.
        // This also clears SO_BINDTODEVICE, which must be restored before connect.
        let mut address: libc::sockaddr = unsafe { std::mem::zeroed() };
        address.sa_family = libc::AF_UNSPEC as libc::sa_family_t;
        let result = unsafe {
            libc::connect(
                socket.as_raw_fd(),
                (&address as *const libc::sockaddr).cast(),
                std::mem::size_of::<libc::sockaddr>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(Error::L2tp(
                l2tp::Error::Io(std::io::Error::last_os_error()),
            ));
        }

        if let Some(if_name) = bound_interface.as_ref() {
            bind_tunnel_socket(tunnel, if_name)?;
        }

        let remote = l2tp::IpEndpoint::V6(to_ipv6_mapped(*tunnel.remote_addr.read().await));
        tunnel.handle.reconnect_ip(&remote).map_err(Error::L2tp)?;

        let info = tunnel.handle.get().await.map_err(Error::L2tp)?;
        verify_reconnected_endpoint(tunnel_id, bound_interface.as_ref(), &info.encapsulation)
    }

    pub(crate) async fn bind_tunnel_interface(&self, tunnel_id: u32, if_name: &str) -> Result<()> {
        let if_name = l2tp::IfName::new(if_name).map_err(Error::L2tp)?;
        let tunnels = self.tunnels.read().await;
        let tunnel = tunnels
            .get(&tunnel_id)
            .ok_or_else(|| Error::Other("tunnel not found".to_string()))?;
        let mut bound_interface = tunnel.bound_interface.write().await;

        bind_tunnel_socket(tunnel, &if_name)?;
        *bound_interface = Some(if_name);
        Ok(())
    }

    pub(crate) async fn delete_tunnel(&self, tunnel_id: u32) -> Result<()> {
        if !self.has_tunnel(tunnel_id).await {
            return Err(Error::Other(format!("Tunnel not found: {}", tunnel_id)));
        }

        let delete_result = self
            .handle
            .delete_tunnel(l2tp::TunnelId(tunnel_id))
            .await
            .map_err(Error::L2tp);

        let removed = {
            let mut tunnels = self.tunnels.write().await;
            remove_if_delete_succeeded(&mut tunnels, &tunnel_id, delete_result)?
        };
        if removed.is_none() {
            return Err(Error::Other(format!("Tunnel not found: {}", tunnel_id)));
        }

        Ok(())
    }

    pub(crate) async fn has_session(&self, tunnel_id: u32, session_id: u32) -> bool {
        let sessions = {
            let tunnels = self.tunnels.read().await;
            tunnels.get(&tunnel_id).map(|t| Arc::clone(&t.sessions))
        };

        if let Some(sessions) = sessions {
            sessions.read().await.contains_key(&session_id)
        } else {
            false
        }
    }

    pub(crate) async fn add_session(
        &self,
        tunnel_id: u32,
        session_id: u32,
        peer_session_id: u32,
        if_name: &str,
    ) -> Result<()> {
        if self.has_session(tunnel_id, session_id).await {
            return Err(Error::Other(format!(
                "Session exists: {}, tunnel: {}",
                session_id, tunnel_id
            )));
        }

        let sessions = {
            let tunnels = self.tunnels.read().await;
            if let Some(t) = tunnels.get(&tunnel_id) {
                Arc::clone(&t.sessions)
            } else {
                return Err(Error::Other(format!("No such tunnel: {}", tunnel_id)));
            }
        };

        let ifname = l2tp::IfName::new(if_name).map_err(Error::L2tp)?;

        let config = l2tp::SessionConfig {
            tunnel_id: l2tp::TunnelId(tunnel_id),
            session_id: l2tp::SessionId(session_id),
            peer_session_id: l2tp::SessionId(peer_session_id),
            pseudowire_type: l2tp::PseudowireType::Eth,
            l2spec_type: l2tp::L2SpecType::None,
            cookie: l2tp::Cookie::none(),
            peer_cookie: l2tp::Cookie::none(),
            recv_seq: false,
            send_seq: false,
            lns_mode: false,
            recv_timeout_ms: None,
            ifname: Some(ifname),
        };

        let mut handle = self
            .handle
            .create_session(config)
            .await
            .map_err(Error::L2tp)?;

        handle.set_auto_delete(false);

        let session = SessionState {
            interface_name: Arc::new(RwLock::new(if_name.to_string())),
            handle: Arc::new(handle),
        };

        sessions.write().await.insert(session_id, session);

        Ok(())
    }

    pub(crate) async fn modify_session(
        &self,
        tunnel_id: u32,
        session_id: u32,
        ifname: &str,
    ) -> Result<()> {
        let sessions = {
            let tunnels = self.tunnels.read().await;
            if let Some(t) = tunnels.get(&tunnel_id) {
                Arc::clone(&t.sessions)
            } else {
                return Err(Error::Other(format!(
                    "No such session {} in tunnel {}",
                    session_id, tunnel_id
                )));
            }
        };

        let (interface_name, handle) = {
            let sessions = sessions.read().await;
            let session = if let Some(s) = sessions.get(&session_id) {
                s
            } else {
                return Err(Error::Other(format!(
                    "No such session {} in tunnel {}",
                    session_id, tunnel_id
                )));
            };

            (
                Arc::clone(&session.interface_name),
                Arc::clone(&session.handle),
            )
        };

        let cached_ifname = interface_name.read().await.clone();
        let old_ifname = match handle.get().await {
            Ok(info) => {
                if let Some(ifname) = info.ifname {
                    ifname.to_string()
                } else {
                    warn!(
                        "kernel returned no interface name for session {} on tunnel {}; using cached name {}",
                        session_id, tunnel_id, cached_ifname
                    );
                    cached_ifname.clone()
                }
            }
            Err(e) => {
                warn!(
                    "failed to query kernel session {} on tunnel {}: {}; using cached name {}",
                    session_id, tunnel_id, e, cached_ifname
                );
                cached_ifname.clone()
            }
        };

        if old_ifname == ifname {
            if cached_ifname != ifname {
                *interface_name.write().await = ifname.to_string();
            }
            return Ok(());
        }

        rename_interface(&old_ifname, ifname).await?;

        *interface_name.write().await = ifname.to_string();

        Ok(())
    }

    pub(crate) async fn delete_session(&self, tunnel_id: u32, session_id: u32) -> Result<()> {
        let sessions = {
            let tunnels = self.tunnels.read().await;
            if let Some(t) = tunnels.get(&tunnel_id) {
                Arc::clone(&t.sessions)
            } else {
                return Err(Error::Other(format!(
                    "No such session {} on tunnel {}",
                    session_id, tunnel_id
                )));
            }
        };

        if !sessions.read().await.contains_key(&session_id) {
            return Err(Error::Other(format!(
                "No such session {} on tunnel {}",
                session_id, tunnel_id
            )));
        }

        let delete_result = self
            .handle
            .delete_session(l2tp::TunnelId(tunnel_id), l2tp::SessionId(session_id))
            .await
            .map_err(Error::L2tp);

        let removed = {
            let mut sessions = sessions.write().await;
            remove_if_delete_succeeded(&mut sessions, &session_id, delete_result)?
        };
        if removed.is_none() {
            return Err(Error::Other(format!(
                "No such session {} on tunnel {}",
                session_id, tunnel_id
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_if_name, remove_if_delete_succeeded, verify_reconnected_endpoint, State};
    use l2tp::{Encapsulation, IfName, IpEndpoint};
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn reconnect_verification_rejects_unspecified_local_endpoints() {
        let device = IfName::new("underlay0").unwrap();
        for local in [
            IpEndpoint::V4(Ipv4Addr::UNSPECIFIED),
            IpEndpoint::V6(Ipv6Addr::UNSPECIFIED),
        ] {
            let remote = match local {
                IpEndpoint::V4(_) => IpEndpoint::V4(Ipv4Addr::LOCALHOST),
                IpEndpoint::V6(_) => IpEndpoint::V6(Ipv6Addr::LOCALHOST),
            };
            for device in [Some(&device), None] {
                let err = verify_reconnected_endpoint(
                    42,
                    device,
                    &Encapsulation::Ip {
                        local: local.clone(),
                        remote: remote.clone(),
                    },
                )
                .expect_err("a successful connect must not hide an unspecified source");
                let message = err.to_string();
                assert!(message.contains("unspecified local endpoint"));
                assert!(message.contains("tunnel_id=42"));
                assert!(message.contains(device.map(IfName::as_str).unwrap_or("<unbound>")));
            }
        }
    }

    #[test]
    fn reconnect_verification_accepts_selected_local_endpoints() {
        for local in [
            IpEndpoint::V4(Ipv4Addr::LOCALHOST),
            IpEndpoint::V6(Ipv6Addr::LOCALHOST),
            IpEndpoint::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
        ] {
            verify_reconnected_endpoint(
                42,
                None,
                &Encapsulation::Ip {
                    remote: local.clone(),
                    local,
                },
            )
            .unwrap();
        }
    }

    // These tests exercise the real State methods: TunnelHandle cannot be
    // constructed without kernel L2TP support. Run explicitly in a test netns.
    async fn privileged_state(if_name: Option<&str>) -> Option<(State, u32)> {
        const IPPROTO_L2TP: libc::c_int = 115;
        // SAFETY: socket has no pointer arguments; a successful fd is owned below.
        let fd = unsafe {
            libc::socket(
                libc::AF_INET6,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                IPPROTO_L2TP,
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if matches!(
                err.raw_os_error(),
                Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT | libc::ESOCKTNOSUPPORT)
            ) {
                eprintln!("skipping: IPv6 L2TP sockets unavailable: {err}");
                return None;
            }
            panic!("IPv6 L2TP socket probe failed: {err}");
        }
        // SAFETY: fd is a new, valid descriptor returned by socket above.
        drop(unsafe { OwnedFd::from_raw_fd(fd) });

        static NEXT_ID: AtomicU32 = AtomicU32::new(0);
        let state = State::new().await.expect("create L2TP handle");
        for _ in 0..16 {
            let id = 1_000_000_000
                + (std::process::id().wrapping_mul(32) + NEXT_ID.fetch_add(2, Ordering::Relaxed))
                    % 500_000_000;
            match state
                .add_tunnel(id, id + 1, IpAddr::V6(Ipv6Addr::LOCALHOST), if_name)
                .await
            {
                Ok(()) => return Some((state, id)),
                Err(crate::error::Error::L2tp(l2tp::Error::KernelError { code, .. }))
                    if code == libc::EEXIST => {}
                Err(crate::error::Error::L2tp(l2tp::Error::Io(err)))
                    if err.raw_os_error() == Some(libc::EADDRINUSE) => {}
                Err(err) => panic!("add_tunnel failed: {err}"),
            }
        }
        panic!("could not allocate a unique tunnel id");
    }

    fn socket_bound_interface(socket: &l2tp::TunnelSocket) -> String {
        let mut name = [0_u8; libc::IFNAMSIZ];
        let mut len = name.len() as libc::socklen_t;
        // SAFETY: name and len are writable buffers of the advertised sizes.
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                name.as_mut_ptr().cast(),
                &mut len,
            )
        };
        assert_eq!(result, 0, "getsockopt: {}", std::io::Error::last_os_error());
        String::from_utf8(name.into_iter().take_while(|byte| *byte != 0).collect()).unwrap()
    }

    #[tokio::test]
    #[ignore = "requires CAP_NET_ADMIN/root and kernel IPv6 L2TP support"]
    async fn privileged_add_tunnel_records_bound_interface() {
        let Some((state, id)) = privileged_state(Some("lo")).await else {
            return;
        };
        {
            let tunnels = state.tunnels.read().await;
            let tunnel = &tunnels[&id];
            assert_eq!(
                tunnel
                    .bound_interface
                    .read()
                    .await
                    .as_ref()
                    .map(IfName::as_str),
                Some("lo")
            );
            assert_eq!(
                socket_bound_interface(tunnel.handle.socket().unwrap()),
                "lo"
            );
        }
        state.delete_tunnel(id).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires CAP_NET_ADMIN/root and kernel IPv6 L2TP support"]
    async fn privileged_add_tunnel_records_unbound_socket() {
        let Some((state, id)) = privileged_state(None).await else {
            return;
        };
        state.reconnect_tunnel(id).await.unwrap();
        {
            let tunnels = state.tunnels.read().await;
            let tunnel = &tunnels[&id];
            assert!(tunnel.bound_interface.read().await.is_none());
            assert_eq!(socket_bound_interface(tunnel.handle.socket().unwrap()), "");
        }
        state.delete_tunnel(id).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires CAP_NET_ADMIN/root and kernel IPv6 L2TP support"]
    async fn privileged_bind_tunnel_interface_records_only_successful_binding() {
        let Some((state, id)) = privileged_state(None).await else {
            return;
        };
        let missing = "l2tp-missing";
        let missing_cstr = std::ffi::CString::new(missing).unwrap();
        // SAFETY: missing_cstr is a valid, NUL-terminated interface name.
        assert_eq!(unsafe { libc::if_nametoindex(missing_cstr.as_ptr()) }, 0);
        assert!(state.bind_tunnel_interface(id, missing).await.is_err());
        assert!(state.tunnels.read().await[&id]
            .bound_interface
            .read()
            .await
            .is_none());

        state.bind_tunnel_interface(id, "lo").await.unwrap();
        assert!(state.bind_tunnel_interface(id, missing).await.is_err());
        // A late bind must also be restored on every subsequent reconnect.
        for _ in 0..3 {
            state.reconnect_tunnel(id).await.unwrap();
            let tunnels = state.tunnels.read().await;
            let tunnel = &tunnels[&id];
            assert_eq!(
                tunnel
                    .bound_interface
                    .read()
                    .await
                    .as_ref()
                    .map(IfName::as_str),
                Some("lo")
            );
            assert_eq!(
                socket_bound_interface(tunnel.handle.socket().unwrap()),
                "lo"
            );
        }
        state.delete_tunnel(id).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires CAP_NET_ADMIN/root and kernel IPv6 L2TP support"]
    async fn privileged_reconnect_restores_binding_and_kernel_source() {
        let Some((state, id)) = privileged_state(Some("lo")).await else {
            return;
        };
        for _ in 0..3 {
            state.reconnect_tunnel(id).await.unwrap();
            let tunnels = state.tunnels.read().await;
            let tunnel = &tunnels[&id];
            assert_eq!(
                socket_bound_interface(tunnel.handle.socket().unwrap()),
                "lo"
            );
            assert_eq!(
                tunnel.handle.get().await.unwrap().encapsulation,
                Encapsulation::Ip {
                    local: IpEndpoint::V6(Ipv6Addr::LOCALHOST),
                    remote: IpEndpoint::V6(Ipv6Addr::LOCALHOST),
                }
            );
        }
        state.delete_tunnel(id).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires CAP_NET_ADMIN/root and an isolated netns with IPv6 L2TP support"]
    async fn privileged_failed_reconnect_retains_binding_for_retry() {
        let Some((state, id)) = privileged_state(Some("lo")).await else {
            return;
        };
        {
            let tunnels = state.tunnels.read().await;
            // The isolated test namespace has only loopback, with no route here.
            *tunnels[&id].remote_addr.write().await = "2001:db8::dead".parse().unwrap();
        }
        assert!(state.reconnect_tunnel(id).await.is_err());
        {
            let tunnels = state.tunnels.read().await;
            let tunnel = &tunnels[&id];
            assert_eq!(
                tunnel
                    .bound_interface
                    .read()
                    .await
                    .as_ref()
                    .map(IfName::as_str),
                Some("lo")
            );
            assert_eq!(
                socket_bound_interface(tunnel.handle.socket().unwrap()),
                "lo"
            );
            *tunnel.remote_addr.write().await = IpAddr::V6(Ipv6Addr::LOCALHOST);
        }
        state
            .reconnect_tunnel(id)
            .await
            .expect("retry with a reachable route");
        {
            let tunnels = state.tunnels.read().await;
            let tunnel = &tunnels[&id];
            assert_eq!(
                socket_bound_interface(tunnel.handle.socket().unwrap()),
                "lo"
            );
            let Encapsulation::Ip { local, .. } = tunnel.handle.get().await.unwrap().encapsulation
            else {
                panic!("expected IP encapsulation");
            };
            assert_eq!(local, IpEndpoint::V6(Ipv6Addr::LOCALHOST));
        }
        state.delete_tunnel(id).await.unwrap();
    }

    #[test]
    fn remove_if_delete_succeeded_keeps_entry_on_error() {
        let mut map = BTreeMap::from([(1_u32, "tunnel")]);
        let result = remove_if_delete_succeeded(
            &mut map,
            &1_u32,
            Err(crate::error::Error::Other("delete failed".to_string())),
        );
        assert!(result.is_err());
        assert_eq!(map.get(&1_u32), Some(&"tunnel"));
    }

    #[test]
    fn remove_if_delete_succeeded_removes_entry_on_success() {
        let mut map = BTreeMap::from([(1_u32, "tunnel")]);
        let removed = remove_if_delete_succeeded(&mut map, &1_u32, Ok(())).unwrap();
        assert_eq!(removed, Some("tunnel"));
        assert!(map.is_empty());
    }

    #[test]
    fn parse_if_name_rejects_invalid_interface_name() {
        let invalid = "this-interface-name-is-way-too-long";
        let parsed = parse_if_name(Some(invalid));
        assert!(parsed.is_err());
    }

    #[test]
    fn parse_if_name_accepts_none() {
        let parsed = parse_if_name(None).unwrap();
        assert!(parsed.is_none());
    }
}
