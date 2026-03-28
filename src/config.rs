use std::{collections::BTreeMap, path::Path};

use crate::error::*;
use iphost::IpHost;
use l2tp::IfName;

fn merge_opt<T>(dst: &mut Option<T>, src: Option<T>) {
    if let Some(v) = src {
        *dst = Some(v);
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename = "lowercase")]
pub(crate) enum IpVersion {
    V4,
    V6,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
pub(crate) struct PartialConfig {
    #[serde(default)]
    pub(crate) tunnels: BTreeMap<String, PartialTunnelConfig>,
    #[serde(default)]
    pub(crate) sessions: BTreeMap<String, PartialSessionConfig>,
}

impl PartialConfig {
    pub(crate) fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let toml =
            std::fs::read_to_string(path).map_err(|e| Error::InvalidConfig(e.to_string()))?;
        toml::from_str(&toml).map_err(|e| Error::InvalidConfig(e.to_string()))
    }

    pub(crate) fn merge(&mut self, latter: Self) {
        for (key, value) in latter.tunnels {
            let tunnel = self.tunnels.entry(key).or_default();
            tunnel.merge(value);
        }
        for (key, value) in latter.sessions {
            let session = self.sessions.entry(key).or_default();
            session.merge(value);
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
pub(crate) struct PartialTunnelConfig {
    pub(crate) tunnel_id: Option<u32>,
    pub(crate) peer_tunnel_id: Option<u32>,
    pub(crate) ip_version: Option<IpVersion>,
    pub(crate) remote_addr: Option<IpHost>,
    pub(crate) bind_interface: Option<String>,
}

impl PartialTunnelConfig {
    pub(crate) fn merge(&mut self, latter: Self) {
        merge_opt(&mut self.tunnel_id, latter.tunnel_id);
        merge_opt(&mut self.peer_tunnel_id, latter.peer_tunnel_id);
        merge_opt(&mut self.ip_version, latter.ip_version);
        merge_opt(&mut self.remote_addr, latter.remote_addr);
        merge_opt(&mut self.bind_interface, latter.bind_interface);
    }

    pub(crate) fn into_full(self) -> Result<TunnelConfig> {
        let tunnel_id = self
            .tunnel_id
            .ok_or(Error::InvalidConfig("tunnel_id is missing".to_string()))?;

        if tunnel_id == 0 {
            return Err(Error::InvalidConfig("tunnel_id is zero".to_string()));
        }

        let peer_tunnel_id = self.peer_tunnel_id.unwrap_or(tunnel_id);
        if peer_tunnel_id == 0 {
            return Err(Error::InvalidConfig("peer_tunnel_id is zero".to_string()));
        }

        let ip_version = self
            .ip_version
            .ok_or(Error::InvalidConfig("ip_version is missing".to_string()))?;
        let remote_addr = self
            .remote_addr
            .ok_or(Error::InvalidConfig("remote_addr is missing".to_string()))?;
        let bind_interface = self.bind_interface;

        if let Some(s) = &bind_interface {
            IfName::new(s).map_err(|e| Error::L2tp(e))?;
        }

        Ok(TunnelConfig {
            tunnel_id,
            peer_tunnel_id,
            ip_version,
            remote_addr,
            bind_interface,
        })
    }
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
pub(crate) struct PartialSessionConfig {
    pub(crate) tunnel_name: Option<String>,
    pub(crate) session_id: Option<u32>,
    pub(crate) peer_session_id: Option<u32>,
    pub(crate) interface_name: Option<String>,
}

impl PartialSessionConfig {
    pub(crate) fn merge(&mut self, latter: Self) {
        merge_opt(&mut self.tunnel_name, latter.tunnel_name);
        merge_opt(&mut self.session_id, latter.session_id);
        merge_opt(&mut self.peer_session_id, latter.peer_session_id);
        merge_opt(&mut self.interface_name, latter.interface_name);
    }

    pub(crate) fn into_full(self) -> Result<SessionConfig> {
        let tunnel_name = self
            .tunnel_name
            .ok_or(Error::InvalidConfig("tunnel_name is missing".to_string()))?;
        let session_id = self
            .session_id
            .ok_or(Error::InvalidConfig("session_id is missing".to_string()))?;

        if session_id == 0 {
            return Err(Error::InvalidConfig("session_id is zero".to_string()));
        }

        let peer_session_id = self.peer_session_id.unwrap_or(session_id);

        if peer_session_id == 0 {
            return Err(Error::InvalidConfig("peer_session_id is zero".to_string()));
        }

        let interface_name = self.interface_name.ok_or(Error::InvalidConfig(
            "interface_name is missing".to_string(),
        ))?;

        IfName::new(&interface_name).map_err(|e| Error::L2tp(e))?;

        Ok(SessionConfig {
            tunnel_name,
            session_id,
            peer_session_id,
            interface_name,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub(crate) struct Config {
    #[serde(default)]
    pub(crate) tunnels: BTreeMap<String, TunnelConfig>,
    #[serde(default)]
    pub(crate) sessions: BTreeMap<String, SessionConfig>,
}

impl Config {
    pub(crate) fn from_partial(partial: PartialConfig) -> Result<Self> {
        let mut full = Config::default();
        for (k, v) in partial.tunnels {
            let tunnel = v.into_full()?;
            full.tunnels.insert(k, tunnel);
        }
        for (k, v) in partial.sessions {
            let session = v.into_full()?;
            if !full.tunnels.contains_key(&session.tunnel_name) {
                return Err(Error::InvalidConfig(format!(
                    "tunnel not defined: {}",
                    &session.tunnel_name
                )));
            }
            full.sessions.insert(k, session);
        }

        Ok(full)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct TunnelConfig {
    pub(crate) tunnel_id: u32,
    pub(crate) peer_tunnel_id: u32,
    pub(crate) ip_version: IpVersion,
    pub(crate) remote_addr: IpHost,
    pub(crate) bind_interface: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct SessionConfig {
    pub(crate) tunnel_name: String,
    pub(crate) session_id: u32,
    pub(crate) peer_session_id: u32,
    pub(crate) interface_name: String,
}
