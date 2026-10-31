//! Tunnel operations (T1–T29): creation on an unconnected socket of the
//! right family, deletion by closing, and the connection converged by the
//! one three-step reconnect.

use std::io;
use std::net::IpAddr;

use nix::errno::Errno;

use crate::config::{Family, TunnelConfig};
use crate::kernel::{Kernel, Peer, errno};

use super::ladder::Target;
use super::records::{ConflictIdentity, Connection, TunnelRecord};
use super::{DELETION_WAIT, RETRY, Reconciler, report};

fn is(error: &io::Error, errnos: &[Errno]) -> bool {
    errnos.iter().any(|e| *e as i32 == errno(error))
}

impl<K: Kernel> Reconciler<K> {
    pub(super) fn tunnel_label(&self, tunnel_id: u32) -> String {
        let name = self.tunnels.get(&tunnel_id).map_or("", |r| r.name.as_str());
        report::tunnel(name, tunnel_id)
    }

    /// Whether the accepted configuration still wants the tunnel record of
    /// `tunnel_id`: an entry of the same kernel identity (C14, T23).
    pub(super) fn tunnel_wanted(&self, tunnel_id: u32) -> Option<(String, TunnelConfig)> {
        let record = self.tunnels.get(&tunnel_id)?;
        let name = self.wanted_tunnels.get(&tunnel_id)?;
        let tunnel = &self.accepted.tunnels()[name];
        (tunnel.identity() == record.identity).then(|| (name.clone(), tunnel.clone()))
    }

    /// Takes over a tunnel socket a previous instance handed over, named
    /// `tunnel_id` by the store (P14, S28): the descriptor must carry that
    /// tunnel. Its sessions are kept as adopted, unmanageable records; the
    /// first reconcile keeps those the configuration has, by kernel
    /// identity, and deletes the others by identifier.
    pub fn adopt(&mut self, tunnel_id: u32, fd: std::os::fd::OwnedFd) -> crate::Result<()> {
        self.inherit(format!("t{tunnel_id}"), fd);
        Ok(())
    }

    pub(super) fn record_adopted(&mut self, adopted: crate::kernel::Adopted) -> crate::Result<()> {
        let tunnel_id = adopted.tunnel_id;
        let config = TunnelConfig::builder(tunnel_id)
            .peer_tunnel_id(adopted.peer_tunnel_id)
            .ip_version(adopted.family)
            .build()?;
        let identity = crate::config::TunnelIdentity::new(tunnel_id, adopted.peer_tunnel_id);
        let mut found = Vec::new();
        self.k
            .scan_sessions(Some(tunnel_id), &mut |s| found.push(s.clone()))?;
        for s in found {
            if let Some(name) = s.ifname {
                self.reserved.insert(name, (tunnel_id, s.session_id));
            }
            let reported = s.cookies().ok().map(|(cookie, peer_cookie)| {
                crate::config::SessionIdentity::new(
                    identity,
                    s.session_id,
                    s.peer_session_id,
                    cookie,
                    peer_cookie,
                )
            });
            let matched = self.wanted_sessions.get(&s.session_id).filter(|name| {
                reported.is_some() && self.accepted.session_identity(name) == reported
            });
            let Some(name) = matched else {
                // Foreign cookie lengths and identifiers that a configuration
                // cannot hold are unmatched too; never construct a fake config.
                self.unmatched_sessions.insert((tunnel_id, s.session_id));
                continue;
            };
            let config = &self.accepted.sessions()[name];
            self.sessions.insert(
                s.session_id,
                super::records::SessionRecord {
                    name: name.clone(),
                    config: config.clone(),
                    identity: reported.unwrap(),
                    tunnel_id,
                    state: super::records::Identity::Adopted,
                    created_as: s.ifname,
                    current_name: None,
                    name_state: super::records::Enforce::Pending,
                    hwaddr: config.interface_hwaddr(),
                    hwaddr_state: super::records::Enforce::Pending,
                    kernel_hwaddr: None,
                },
            );
        }
        self.tunnels.insert(
            tunnel_id,
            TunnelRecord {
                name: String::new(),
                config,
                identity,
                socket: adopted.socket,
                family: adopted.family,
                bound: None,
                bind_index: None,
                zone_index: None,
                connection: Connection::Disconnected { pending: None },
                // Its connection is unknown: the first converge disconnects.
                stale: true,
            },
        );
        log::info!(
            "{}: adopted from the previous instance",
            report::tunnel("", tunnel_id)
        );
        Ok(())
    }

    /// Takes configuration changes that apply in place (T22): the record
    /// keeps its socket; converging applies the new peer and binding.
    pub(super) fn update_tunnels_in_place(&mut self) {
        let ids: Vec<u32> = self.tunnels.keys().copied().collect();
        for id in ids {
            if let Some((name, config)) = self.tunnel_wanted(id) {
                let record = self.tunnels.get_mut(&id).unwrap();
                if record.name != name || record.config != config {
                    self.report.forget(&report::tunnel(&record.name, id));
                }
                record.name = name;
                record.config = config;
            }
        }
    }

    /// Closes the sockets of the tunnels the configuration no longer has,
    /// after their sessions (S26, T8).
    pub(super) fn remove_unwanted_tunnels(&mut self) {
        let unwanted: Vec<u32> = self
            .tunnels
            .keys()
            .copied()
            .filter(|id| self.tunnel_wanted(*id).is_none())
            .collect();
        for id in unwanted {
            // Sessions that could not be deleted go with the tunnel (K17).
            let orphans: Vec<u32> = self
                .sessions
                .iter()
                .filter(|(_, s)| s.tunnel_id == id)
                .map(|(k, _)| *k)
                .collect();
            for sid in orphans {
                self.forget_session(sid);
            }
            let label = self.tunnel_label(id);
            self.verify_tunnels.remove(&id);
            let unmatched: Vec<_> = self
                .unmatched_sessions
                .iter()
                .copied()
                .filter(|(tid, _)| *tid == id)
                .collect();
            for (tid, sid) in unmatched {
                self.unmatched_sessions.remove(&(tid, sid));
                self.report.forget(&report::session("", tid, sid));
            }
            let record = self.tunnels.remove(&id).unwrap();
            self.retries.remove(&id);
            if !self.withdraw_socket(id, record.socket) {
                self.k.close(record.socket);
                self.departing.insert(id, self.k.now() + DELETION_WAIT);
            }
            if !self.wanted_tunnels.contains_key(&id) {
                self.resolvers.forget(id);
            }
            self.report.forget(&label);
            log::info!("{label}: removed");
        }
    }

    /// Lets go of identifiers the kernel released, or after the wait (T8).
    pub(super) fn release_departed(&mut self) {
        let now = self.k.now();
        let ids: Vec<(u32, std::time::Instant)> =
            self.departing.iter().map(|(k, v)| (*k, *v)).collect();
        for (id, deadline) in ids {
            if deadline <= now || matches!(self.k.tunnel(id), Ok(None)) {
                self.departing.remove(&id);
            }
        }
        for (key, deadline) in self
            .deleting_sessions
            .iter()
            .map(|(key, at)| (*key, *at))
            .collect::<Vec<_>>()
        {
            if deadline <= now || matches!(self.k.session(key.0, key.1), Ok(None)) {
                self.deleting_sessions.remove(&key);
            }
        }
        let departed: Vec<_> = self
            .reserved
            .iter()
            .filter(|(_, (_, sid))| !self.sessions.contains_key(sid))
            .map(|(name, ids)| (*name, *ids))
            .collect();
        for (name, (tid, sid)) in departed {
            if matches!(self.k.session(tid, sid), Ok(None)) {
                self.reserved.remove(&name);
                self.deleting_sessions.remove(&(tid, sid));
            }
        }
    }

    /// Creates the tunnels the configuration has and the kernel lacks (T6).
    pub(super) fn create_wanted_tunnels(&mut self) {
        let wanted: Vec<(String, TunnelConfig)> = self
            .accepted
            .tunnels()
            .iter()
            .filter(|(_, t)| !self.tunnels.contains_key(&t.tunnel_id()))
            .map(|(n, t)| (n.clone(), t.clone()))
            .collect();
        for (name, config) in wanted {
            let id = config.tunnel_id();
            if self.departing.contains_key(&id) || self.store.blocks(id) {
                self.incomplete = true;
                continue;
            }
            let identity = ConflictIdentity::Tunnel(config.identity());
            if !self.may_try(false, id, identity) {
                continue;
            }
            let label = report::tunnel(&name, id);
            match self.create_tunnel(&name, &config) {
                Ok(()) => {
                    self.conflict_over(false, id, &label);
                    self.report.end(&label, "defect", || "created".into());
                }
                Err(e) if is(&e, &[Errno::EEXIST, Errno::EADDRINUSE]) => {
                    self.conflict(false, id, identity, &label, &e)
                }
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock && self.tunable_pending.is_some() =>
                {
                    self.incomplete = true;
                }
                Err(e) => {
                    self.incomplete = true;
                    self.report.cannot_create(&label, "defect", &e);
                }
            }
        }
    }

    /// A socket of the family T3, T4 and T26 select, the tunnel registered
    /// on it, unconnected.
    fn create_tunnel(&mut self, name: &str, config: &TunnelConfig) -> io::Result<()> {
        if self.accepted.host().fix_bindv6only() && self.tunable_pending.is_some() {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let (id, peer_id) = (config.tunnel_id(), config.peer_tunnel_id());
        let label = report::tunnel(name, id);
        let provisional = match self.k.create_socket(Family::V6, id, peer_id) {
            Ok(socket) => match self.k.only_v6(socket) {
                Ok(only) => Ok((socket, only)),
                Err(error) => {
                    self.k.close(socket);
                    return Err(error);
                }
            },
            Err(error) => Err(error),
        };
        let (socket, family) = match provisional {
            Ok((socket, true)) => {
                // T26: bindv6only is set; ask for the fix, and meanwhile a
                // V4 tunnel takes an AF_INET socket.
                if self.accepted.host().fix_bindv6only() && self.tunable.is_none() {
                    self.k.close(socket);
                    self.request_tunable();
                    return Err(io::Error::from(io::ErrorKind::WouldBlock));
                }
                self.report.begin(&label, "v6only", || {
                    "IPv6 sockets are IPv6-only (bindv6only); in-place family moves are unavailable (T26)".into()
                });
                if config.family() == Family::V4 {
                    self.k.close(socket);
                    (self.k.create_socket(Family::V4, id, peer_id)?, Family::V4)
                } else {
                    (socket, Family::V6)
                }
            }
            Ok((socket, false)) => {
                self.inet6_refused = false;
                (socket, Family::V6)
            }
            Err(e) if is(&e, &[Errno::EAFNOSUPPORT, Errno::EPROTONOSUPPORT]) => {
                if !self.inet6_refused {
                    self.inet6_refused = true;
                    log::warn!(
                        "AF_INET6 L2TP/IP sockets are refused ({}); tunnels use AF_INET sockets (T4)",
                        report::describe(&e)
                    );
                }
                (self.k.create_socket(Family::V4, id, peer_id)?, Family::V4)
            }
            Err(e) => return Err(e),
        };
        let bind = match config
            .bind_interface()
            .map(|name| self.k.link_by_name(name))
            .transpose()
        {
            Ok(link) => link.flatten().map(|link| link.index),
            Err(error) => {
                self.k.close(socket);
                return Err(error);
            }
        };
        if let Some(index) = bind
            && let Err(error) = self.k.bind_index(socket, index)
        {
            self.k.close(socket);
            return Err(error);
        }
        if let Err(e) = self.k.register_tunnel(socket, id, peer_id) {
            self.k.close(socket);
            return Err(e);
        }
        self.tunnels.insert(
            id,
            TunnelRecord {
                name: name.to_owned(),
                config: config.clone(),
                identity: config.identity(),
                socket,
                family,
                bound: bind,
                bind_index: bind,
                zone_index: None,
                connection: Connection::Disconnected { pending: None },
                stale: false,
            },
        );
        self.store_socket(id, socket);
        log::info!("{label}: created");
        Ok(())
    }

    /// Converges one tunnel's binding and connection to its target (T1,
    /// T2). Returns false when something is left to retry.
    pub(super) fn converge_tunnel(&mut self, id: u32) -> bool {
        self.unindex_tunnel(id);
        let result = self.converge_tunnel_inner(id);
        self.index_tunnel(id);
        self.retain_devices();
        result
    }

    fn converge_tunnel_inner(&mut self, id: u32) -> bool {
        let label = self.tunnel_label(id);
        let target = match self.target(id) {
            Ok(target) => target,
            Err(e) => {
                log::debug!("{label}: device lookup failed: {}", report::describe(&e));
                self.arm_retry(id);
                return false;
            }
        };
        let record = &self.tunnels[&id];
        match target {
            Target::Connect { peer, bind, zone } => {
                let converged = matches!(&record.connection, Connection::Connected { peer: p, .. } if *p == peer)
                    && record.bind_index == bind
                    && record.zone_index == zone
                    && !record.stale;
                converged || self.reconnect(id, peer, bind, zone)
            }
            Target::Disconnect { bind, pending, why } => {
                if !self.disconnect_to(id, bind, pending.clone()) {
                    return false;
                }
                match (why, pending) {
                    (Some(why), Some(_)) => {
                        self.report
                            .begin(&label, "pending", || format!("disconnected: {why}"));
                        self.arm_retry(id);
                        false
                    }
                    _ => true,
                }
            }
        }
    }

    /// Leaves the tunnel disconnected, bound to `bind` when it is present
    /// (T6, T11–T13).
    fn disconnect_to(&mut self, id: u32, bind: Option<u32>, pending: Option<Peer>) -> bool {
        let label = self.tunnel_label(id);
        let record = &self.tunnels[&id];
        if !record.stale
            && record.bound == bind
            && record.zone_index.is_none()
            && record.connection
                == (Connection::Disconnected {
                    pending: pending.clone(),
                })
        {
            return true;
        }
        let socket = record.socket;
        let connected = record.connection.is_connected();
        if let Err(error) = self.k.disconnect(socket) {
            self.report.begin_error(&label, "disconnect", || {
                format!("disconnect failed: {}", report::describe(&error))
            });
            self.arm_retry(id);
            return false;
        }
        self.report
            .end(&label, "disconnect", || "disconnected".into());
        let record = self.tunnels.get_mut(&id).unwrap();
        record.bound = None;
        record.connection = Connection::Disconnected { pending };
        record.bind_index = bind;
        record.zone_index = None;
        record.stale = false;
        if connected {
            log::info!("{label}: disconnected");
        }
        if let Some(index) = bind {
            match self.k.bind_index(socket, index) {
                Ok(()) => self.tunnels.get_mut(&id).unwrap().bound = Some(index),
                Err(error) => {
                    self.report.begin(&label, "bind", || {
                        format!("bind failed: {}", report::describe(&error))
                    });
                    self.arm_retry(id);
                    return false;
                }
            }
        }
        self.report.forget_condition(&label, "bind");
        true
    }

    /// The reconnect of T21: disconnect, bind to the device the name
    /// resolves to now, connect; the source read back after it (T28).
    fn reconnect(&mut self, id: u32, peer: Peer, bind: Option<u32>, zone: Option<u32>) -> bool {
        let label = self.tunnel_label(id);
        let socket = self.tunnels[&id].socket;
        // kernel: net/ipv6/datagram.c ip6_datagram_connect may retain a scope on failure (K27).
        if let Err(e) = self.k.disconnect(socket) {
            self.report.begin_error(&label, "disconnect", || {
                format!("disconnect failed: {}", report::describe(&e))
            });
            self.arm_retry(id);
            return false;
        }
        self.report
            .end(&label, "disconnect", || "disconnected".into());
        let record = self.tunnels.get_mut(&id).unwrap();
        record.bound = None;
        record.connection = Connection::Disconnected {
            pending: Some(peer.clone()),
        };
        record.bind_index = bind;
        record.zone_index = zone;
        record.stale = false;
        let result = match bind {
            Some(index) => self.k.bind_index(socket, index).map(|()| {
                self.tunnels.get_mut(&id).unwrap().bound = Some(index);
            }),
            None => Ok(()),
        }
        .and_then(|()| self.k.connect(socket, &peer));
        match result {
            Ok(source) if !source.to_canonical().is_unspecified() => {
                let record = self.tunnels.get_mut(&id).unwrap();
                record.connection = Connection::Connected {
                    peer: peer.clone(),
                    source: source.to_canonical(),
                };
                record.bound = zone.or(bind);
                self.retries.remove(&id);
                self.report.forget_condition(&label, "pending");
                log::info!(
                    "{label}: connected to {} from {}",
                    peer.addr,
                    source.to_canonical()
                );
                true
            }
            outcome => {
                self.tunnels.get_mut(&id).unwrap().stale = true;
                // T20, T28: no source selected is a failed connect.
                if outcome.is_ok() {
                    let _ = self.k.disconnect(socket);
                    self.tunnels.get_mut(&id).unwrap().bound = None;
                }
                let why = match &outcome {
                    Err(e) => report::describe(e),
                    Ok(_) => "no source address was selected".into(),
                };
                if let Err(e) = &outcome
                    && is(e, &[Errno::EAFNOSUPPORT, Errno::EPERM])
                {
                    log::error!(
                        "{label}: connect to {} refused as a daemon defect: {why}",
                        peer.addr
                    );
                }
                self.report.begin(&label, "pending", || {
                    format!("disconnected, peer {} pending: {why}", peer.addr)
                });
                self.arm_retry(id);
                false
            }
        }
    }

    /// Queues a retry a second later, without postponing one queued (E8).
    pub(super) fn arm_retry(&mut self, id: u32) {
        let at = self.k.now() + RETRY;
        if !self.retries.contains_key(&id) {
            self.retries.insert(id, at);
        }
    }

    /// The source a connected tunnel reported (E7).
    pub(super) fn source_of(&self, id: u32) -> Option<IpAddr> {
        match &self.tunnels.get(&id)?.connection {
            Connection::Connected { source, .. } => Some(*source),
            _ => None,
        }
    }
}

impl<K: Kernel> Reconciler<K> {
    pub(super) fn retry_unmatched_sessions(&mut self) {
        for (tid, sid) in self.unmatched_sessions.clone() {
            let label = report::session("", tid, sid);
            match self.k.delete_session(tid, sid) {
                Ok(()) => {
                    self.unmatched_sessions.remove(&(tid, sid));
                    self.deleting_sessions
                        .insert((tid, sid), self.k.now() + DELETION_WAIT);
                    self.report.forget_condition(&label, "adoption-delete");
                    log::info!("{label}: unmatched adopted session deleted (S28)");
                }
                Err(error) if errno(&error) == Errno::ENODEV as i32 => {
                    self.unmatched_sessions.remove(&(tid, sid));
                    self.report.forget(&label);
                }
                Err(error) => {
                    self.incomplete = true;
                    self.report.begin_error(&label, "adoption-delete", || {
                        format!("unmatched adopted session deletion failed: {error}")
                    });
                }
            }
        }
    }
}
