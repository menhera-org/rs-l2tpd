
use crate::error::{Result, Error};

use futures_util::TryStreamExt;
use rtnetlink::LinkUnspec;

use tokio::sync::RwLock;

use std::{collections::BTreeMap, net::{IpAddr, Ipv6Addr}, sync::Arc};

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

pub(crate) fn to_ipv6_mapped(addr: IpAddr) -> Ipv6Addr {
    match addr {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

pub(crate) struct SessionState {
    pub(crate) interface_name: Arc<RwLock<String>>,
    pub(crate) handle: l2tp::SessionHandle,
}

pub(crate) struct TunnelState {
    pub(crate) remote_addr: Arc<RwLock<IpAddr>>,
    pub(crate) handle: l2tp::TunnelHandle,

    /// session_id to SessionState
    pub(crate) sessions: Arc<RwLock<BTreeMap<u32, SessionState>>>,
}

pub(crate) struct State {
    pub(crate) handle: l2tp::L2tpHandle,

    /// tunnel_id to TunnelState
    pub(crate) tunnels: Arc<RwLock<BTreeMap<u32, TunnelState>>>,
}

impl State {
    pub(crate) async fn new() -> Result<Self> {
        let handle = l2tp::L2tpHandle::new().await.map_err(|e| Error::L2tp(e))?;
        let tunnels = Arc::new(RwLock::new(BTreeMap::new()));
        Ok(Self {
            handle,
            tunnels,
        })
    }

    pub(crate) async fn has_tunnel(&self, tunnel_id: u32) -> bool {
        self.tunnels.read().await.contains_key(&tunnel_id)
    }

    pub(crate) async fn add_tunnel(&self, tunnel_id: u32, peer_tunnel_id: u32, remote_addr: IpAddr, if_name: Option<&str>) -> Result<()> {
        if self.has_tunnel(tunnel_id).await {
            return Err(Error::Other("Duplicate tunnel_id".to_string()));
        }

        let if_name = if let Some(s) = if_name {
            l2tp::IfName::new(s).ok()
        } else {
            None
        };

        let local = l2tp::IpEndpoint::V6(Ipv6Addr::UNSPECIFIED);
        let remote = l2tp::IpEndpoint::V6(to_ipv6_mapped(remote_addr));

        let socket = l2tp::TunnelSocket::ip(
            &local,
            &remote,
            if_name.as_ref(),
            tunnel_id,
        ).map_err(|e| Error::L2tp(e))?;

        let config = l2tp::TunnelConfig::new(
            l2tp::TunnelId(tunnel_id),
            l2tp::TunnelId(peer_tunnel_id),
            l2tp::Encapsulation::Ip {
                local,
                remote,
            },
        ).map_err(|e| Error::L2tp(e))?;

        let mut handle = self.handle.create_tunnel(config, socket).await
            .map_err(|e| Error::L2tp(e))?;

        handle.set_auto_delete(false);

        let tunnel = TunnelState {
            remote_addr: Arc::new(RwLock::new(remote_addr)),
            handle,
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
        tunnel.handle.reconnect_ip(&new_remote).map_err(|e| Error::L2tp(e))?;

        *tunnel.remote_addr.write().await = remote_addr;

        Ok(())
    }

    pub(crate) async fn delete_tunnel(&self, tunnel_id: u32) -> Result<()> {
        let tunnel = {
            let mut tunnels = self.tunnels.write().await;
            if let Some(t) = tunnels.remove(&tunnel_id) {
                t
            } else {
                return Err(Error::Other(format!("Tunnel not found: {}", tunnel_id)));
            }
        };

        self.handle.delete_tunnel(l2tp::TunnelId(tunnel_id)).await
            .map_err(|e| Error::L2tp(e))?;

        drop(tunnel);

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

    pub(crate) async fn add_session(&self, tunnel_id: u32, session_id: u32, peer_session_id: u32, if_name: &str) -> Result<()> {
        if self.has_session(tunnel_id, session_id).await {
            return Err(Error::Other(format!("Session exists: {}, tunnel: {}", session_id, tunnel_id)));
        }

        let sessions = {
            let tunnels = self.tunnels.read().await;
            if let Some(t) = tunnels.get(&tunnel_id) {
                Arc::clone(&t.sessions)
            } else {
                return Err(Error::Other(format!("No such tunnel: {}", tunnel_id)));
            }
        };

        let ifname = l2tp::IfName::new(if_name)
            .map_err(|e| Error::L2tp(e))?;

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

        let mut handle = self.handle.create_session(config).await
            .map_err(|e| Error::L2tp(e))?;

        handle.set_auto_delete(false);

        let session = SessionState {
            interface_name: Arc::new(RwLock::new(if_name.to_string())),
            handle,
        };

        sessions.write().await.insert(session_id, session);

        Ok(())
    }

    pub(crate) async fn modify_session(&self, tunnel_id: u32, session_id: u32, ifname: &str) -> Result<()> {
        let sessions = {
            let tunnels = self.tunnels.read().await;
            if let Some(t) = tunnels.get(&tunnel_id) {
                Arc::clone(&t.sessions)
            } else {
                return Err(Error::Other(format!("No such session {} in tunnel {}", session_id, tunnel_id)));
            }
        };

        let (interface_name, old_ifname) = {
            let sessions = sessions.read().await;
            let session = if let Some(s) = sessions.get(&session_id) {
                s
            } else {
                return Err(Error::Other(format!("No such session {} in tunnel {}", session_id, tunnel_id)));
            };

            let old_ifname = if let Some(n) = session.handle.get().await.map(|i| i.ifname).ok().flatten() {
                n
            } else {
                return Err(Error::Other(format!("Session {} on tunnel {} has no interface name", session_id, tunnel_id)));
            }.to_string();

            (Arc::clone(&session.interface_name), old_ifname)
        };

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
                return Err(Error::Other(format!("No such session {} on tunnel {}", session_id, tunnel_id)));
            }
        };

        let session = if let Some(s) = sessions.write().await.remove(&session_id) {
            s
        } else {
            return Err(Error::Other(format!("No such session {} on tunnel {}", session_id, tunnel_id)));
        };

        self.handle.delete_session(l2tp::TunnelId(tunnel_id), l2tp::SessionId(session_id)).await
            .map_err(|e| Error::L2tp(e))?;

        drop(session);

        Ok(())
    }
}
