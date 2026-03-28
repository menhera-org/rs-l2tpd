
use crate::error::{Result, Error};

use std::{collections::BTreeMap, net::{IpAddr, Ipv6Addr}};

pub(crate) fn to_ipv6_mapped(addr: IpAddr) -> Ipv6Addr {
    match addr {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

pub(crate) struct SessionState {
    pub(crate) interface_name: String,
    pub(crate) handle: l2tp::SessionHandle,
}

pub(crate) struct TunnelState {
    pub(crate) remote_addr: IpAddr,
    pub(crate) handle: l2tp::TunnelHandle,

    /// session_id to SessionState
    pub(crate) sessions: BTreeMap<u32, SessionState>,
}

pub(crate) struct State {
    pub(crate) handle: l2tp::L2tpHandle,

    /// tunnel_id to TunnelState
    pub(crate) tunnels: BTreeMap<u32, TunnelState>,
}

impl State {
    pub(crate) async fn new() -> Result<Self> {
        let handle = l2tp::L2tpHandle::new().await.map_err(|e| Error::L2tp(e))?;
        let tunnels = BTreeMap::new();
        Ok(Self {
            handle,
            tunnels,
        })
    }

    pub(crate) fn has_tunnel(&self, tunnel_id: u32) -> bool {
        self.tunnels.contains_key(&tunnel_id)
    }

    pub(crate) async fn add_tunnel(&mut self, tunnel_id: u32, peer_tunnel_id: u32, remote_addr: IpAddr, if_name: Option<&str>) -> Result<()> {
        if self.has_tunnel(tunnel_id) {
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

        let handle = self.handle.create_tunnel(config, socket).await
            .map_err(|e| Error::L2tp(e))?;

        let tunnel = TunnelState {
            remote_addr,
            handle,
            sessions: BTreeMap::new(),
        };

        self.tunnels.insert(tunnel_id, tunnel);

        Ok(())
    }

    pub(crate) fn modify_tunnel(&mut self, tunnel_id: u32, remote_addr: IpAddr) -> Result<()> {
        let tunnel = if let Some(t) = self.tunnels.get_mut(&tunnel_id) {
            t
        } else {
            return Err(Error::Other("tunnel not found".to_string()));
        };

        if tunnel.remote_addr == remote_addr {
            return Ok(());
        }

        let new_remote = l2tp::IpEndpoint::V6(to_ipv6_mapped(remote_addr));
        tunnel.handle.reconnect_ip(&new_remote).map_err(|e| Error::L2tp(e))?;

        tunnel.remote_addr = remote_addr;

        Ok(())
    }

    pub(crate) async fn delete_tunnel(&mut self, tunnel_id: u32) -> Result<()> {
        let tunnel = if let Some(t) = self.tunnels.remove(&tunnel_id) {
            t
        } else {
            return Err(Error::Other(format!("Tunnel not found: {}", tunnel_id)))
        };

        self.handle.delete_tunnel(l2tp::TunnelId(tunnel_id)).await
            .map_err(|e| Error::L2tp(e))?;

        drop(tunnel);

        Ok(())
    }
}
