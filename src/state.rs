//! Kernel-facing operations: tunnels, sessions and their devices.
//!
//! This module is private; [`crate::runtime::Runtime`] owns the only
//! instance and decides when each operation runs.

use crate::config::HwAddr;
use crate::error::{Error, Result};

use futures_util::TryStreamExt;
use l2tp::{L2tpIfName, L2tpIfNameExt};
use log::{debug, info, warn};
use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
use rtnetlink::LinkUnspec;

use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv6Addr},
    sync::Arc,
};

/// A route netlink connection whose driver task ends with the value.
struct Rtnl {
    handle: rtnetlink::Handle,
    connection: JoinHandle<()>,
}

impl Rtnl {
    fn connect() -> Result<Self> {
        let (connection, handle, _) = rtnetlink::new_connection()
            .map_err(|e| Error::Other(format!("failed to create netlink connection: {e}")))?;
        let connection = tokio::spawn(connection);
        Ok(Self { handle, connection })
    }

    async fn get_link(&self, index: u32) -> Result<LinkMessage> {
        let mut links = self.handle.link().get().match_index(index).execute();
        links
            .try_next()
            .await
            .map_err(|e| Error::Other(format!("failed to look up interface index {index}: {e}")))?
            .ok_or_else(|| Error::Other(format!("interface index {index} not found")))
    }

    async fn set_link(&self, message: LinkMessage) -> std::result::Result<(), rtnetlink::Error> {
        self.handle.link().set(message).execute().await
    }
}

impl Drop for Rtnl {
    fn drop(&mut self) {
        self.connection.abort();
    }
}

fn link_name(link: &LinkMessage) -> Option<L2tpIfName> {
    link.attributes.iter().find_map(|attr| match attr {
        LinkAttribute::IfName(name) => L2tpIfName::from_name(name).ok(),
        _ => None,
    })
}

fn link_hwaddr(link: &LinkMessage) -> Option<HwAddr> {
    link.attributes.iter().find_map(|attr| match attr {
        LinkAttribute::Address(bytes) => HwAddr::from_kernel(bytes),
        _ => None,
    })
}

fn link_is_up(link: &LinkMessage) -> bool {
    link.header.flags.contains(LinkFlags::Up)
}

fn is_netlink_errno(err: &rtnetlink::Error, errno: i32) -> bool {
    matches!(err, rtnetlink::Error::NetlinkError(msg) if msg.raw_code().abs() == errno)
}

/// Renames the interface with index `index` to `new`.
///
/// Devices are addressed by index because the kernel records a session's
/// interface name only once, at creation, so the name reported later never
/// follows a rename. A rename to the name the device already bears is a
/// no-op.
async fn rename_interface(index: u32, new: &L2tpIfName) -> Result<()> {
    let rtnl = Rtnl::connect()?;
    let link = rtnl.get_link(index).await?;
    if link_name(&link).as_ref() == Some(new) {
        return Ok(());
    }

    let name = new
        .to_str()
        .map_err(|_| Error::Other(format!("non-UTF-8 interface name {new:?}")))?;
    rtnl.set_link(LinkUnspec::new_with_index(index).name(name).build())
        .await
        .map_err(|e| {
            Error::Other(format!(
                "failed to rename interface index {index} to {new}: {e}"
            ))
        })
}

/// Sets the hardware address of the interface with index `index` to
/// `target` and verifies the result.
///
/// An `l2tpeth` device only accepts a new address while it is down. If the
/// device is up, it is taken down for the change and brought up again, so
/// that the configured address is applied rather than silently skipped.
async fn apply_hwaddr(index: u32, target: HwAddr) -> Result<()> {
    let rtnl = Rtnl::connect()?;
    let link = rtnl.get_link(index).await?;
    if link_hwaddr(&link) == Some(target) {
        return Ok(());
    }

    let address_message = || {
        LinkUnspec::new_with_index(index)
            .address(target.octets().to_vec())
            .build()
    };
    let failure = |e: rtnetlink::Error| {
        Error::Other(format!(
            "failed to set hardware address {target} on interface index {index}: {e}"
        ))
    };

    match rtnl.set_link(address_message()).await {
        Ok(()) => {}
        Err(e) if is_netlink_errno(&e, libc::EBUSY) && link_is_up(&link) => {
            info!("interface index {index} is up; taking it down to set hardware address {target}");
            rtnl.set_link(LinkUnspec::new_with_index(index).down().build())
                .await
                .map_err(|e| {
                    Error::Other(format!(
                        "failed to take interface index {index} down for a hardware address change: {e}"
                    ))
                })?;
            let result = rtnl.set_link(address_message()).await.map_err(failure);
            // Bring the device back up whether or not the change succeeded.
            if let Err(e) = rtnl
                .set_link(LinkUnspec::new_with_index(index).up().build())
                .await
            {
                warn!("failed to bring interface index {index} back up: {e}");
                result?;
                return Err(Error::Other(format!(
                    "failed to bring interface index {index} back up after a hardware address change: {e}"
                )));
            }
            result?;
        }
        Err(e) => return Err(failure(e)),
    }

    let link = rtnl.get_link(index).await?;
    match link_hwaddr(&link) {
        Some(current) if current == target => Ok(()),
        current => Err(Error::Other(format!(
            "interface index {index} reports hardware address {} after setting {target}",
            current.map_or_else(|| "<none>".to_string(), |a| a.to_string())
        ))),
    }
}

/// Resolves `if_name` in the daemon's own network namespace.
///
/// `ENODEV` means no interface has this name; any other failure is an error.
pub(crate) async fn interface_index(if_name: &L2tpIfName) -> Result<Option<u32>> {
    match if_name.index() {
        Ok(index) => Ok(Some(index)),
        Err(e) if e.raw_os_error() == Some(libc::ENODEV) => Ok(None),
        Err(e) => Err(Error::Other(format!(
            "failed to look up interface {if_name}: {e}"
        ))),
    }
}

/// The current name of the interface with `index`, or `None` when no
/// interface has this index any more.
pub(crate) async fn interface_name(index: u32) -> Result<Option<L2tpIfName>> {
    match L2tpIfName::from_index(index) {
        Ok(name) => Ok(Some(name)),
        Err(e) if e.raw_os_error() == Some(libc::ENXIO) => Ok(None),
        Err(e) => Err(Error::Other(format!(
            "failed to look up interface index {index}: {e}"
        ))),
    }
}

/// A device a tunnel socket is bound to: the index is its identity, the name
/// is what it was called when the binding was made or last refreshed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BoundDevice {
    pub(crate) name: L2tpIfName,
    pub(crate) index: u32,
}

/// Binds the socket to the device called `name` and captures its identity.
///
/// `SO_BINDTODEVICE` takes a name and the kernel resolves it to an index at
/// that moment. The index is read before and after, and the binding is only
/// recorded when both agree, so a device renamed during the call cannot be
/// mistaken for the one bound.
fn bind_socket_to_named_device(
    socket: &l2tp::TunnelSocket,
    name: &L2tpIfName,
) -> Result<BoundDevice> {
    let before = name.index().map_err(Error::L2tp)?;
    socket.bind_to_device(name).map_err(Error::L2tp)?;
    let after = name.index().map_err(Error::L2tp)?;
    if before != after {
        return Err(Error::Other(format!(
            "interface {name} changed identity (index {before} to {after}) while binding"
        )));
    }
    Ok(BoundDevice {
        name: *name,
        index: after,
    })
}

/// Re-binds the socket to the device identified by `device.index`, whatever
/// it is called now. `ENODEV` from the lookup means the device is gone.
fn rebind_socket_to_device(
    socket: &l2tp::TunnelSocket,
    device: &BoundDevice,
) -> Result<BoundDevice> {
    let current_name = match L2tpIfName::from_index(device.index) {
        Ok(name) => name,
        Err(e) if e.raw_os_error() == Some(libc::ENXIO) => {
            return Err(Error::L2tp(l2tp::Error::Io(
                std::io::Error::from_raw_os_error(libc::ENODEV),
            )));
        }
        Err(e) => return Err(Error::L2tp(e)),
    };
    if current_name != device.name {
        info!(
            "bound interface index {} is now named {} (was {})",
            device.index, current_name, device.name
        );
    }
    let rebound = bind_socket_to_named_device(socket, &current_name)?;
    if rebound.index != device.index {
        return Err(Error::Other(format!(
            "interface {current_name} changed identity (index {} to {}) while rebinding",
            device.index, rebound.index
        )));
    }
    Ok(rebound)
}

pub(crate) fn to_ipv6_mapped(addr: IpAddr) -> Ipv6Addr {
    match addr {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

pub(crate) struct SessionState {
    /// Index of the session's l2tpeth device, from the kernel's registration
    /// broadcast. Renames keep it; names do not survive them.
    index: u32,
    /// The hardware address the kernel assigned at creation, restored when
    /// the configuration stops naming one.
    initial_hwaddr: Option<HwAddr>,
    // Keep session handle alive for the session lifecycle even when we don't call methods on it.
    #[allow(dead_code)]
    handle: l2tp::SessionHandle,
}

pub(crate) struct TunnelState {
    remote_addr: RwLock<IpAddr>,
    handle: l2tp::TunnelHandle,
    // Last successfully applied device, retained across disconnects for retries.
    // The write lock serializes binding and the entire reconnect sequence.
    bound_interface: RwLock<Option<BoundDevice>>,

    /// session_id to SessionState
    sessions: Arc<RwLock<BTreeMap<u32, SessionState>>>,
}

pub(crate) struct State {
    handle: l2tp::L2tpHandle,

    /// tunnel_id to TunnelState
    tunnels: RwLock<BTreeMap<u32, TunnelState>>,
}

fn tunnel_socket(tunnel: &TunnelState) -> Result<&l2tp::TunnelSocket> {
    tunnel
        .handle
        .socket()
        .ok_or_else(|| Error::Other("tunnel has no managed socket".to_string()))
}

fn verify_reconnected_endpoint(
    tunnel_id: u32,
    if_name: Option<&L2tpIfName>,
    encapsulation: &l2tp::Encapsulation,
) -> Result<()> {
    let reason = match encapsulation {
        l2tp::Encapsulation::Ip { local, .. } => {
            if !local.ip().is_unspecified() {
                return Ok(());
            }
            "kernel reports an unspecified local endpoint after reconnect"
        }
        _ => "kernel reports unexpected encapsulation after IP reconnect",
    };
    let message = format!(
        "{reason} tunnel_id={tunnel_id} if_name={}",
        if_name
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "<unbound>".to_string())
    );
    warn!("{message}");
    Err(Error::Other(message))
}

/// Whether a failed deletion still leaves nothing to clean up.
///
/// `DeletionPending` means the kernel acknowledged the deletion and finishes
/// it on its own; `ENODEV` means the object is already gone, for example a
/// session deleted together with its tunnel. Retrying either would only ever
/// fail, so the caller forgets the entry.
fn deletion_is_complete(err: &l2tp::Error) -> bool {
    matches!(err, l2tp::Error::DeletionPending(_)) || err.raw_os_error() == Some(libc::ENODEV)
}

fn deletion_result(what: &str, result: l2tp::Result<()>) -> Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(e) if deletion_is_complete(&e) => {
            debug!("{what} is already being removed: {e}");
            Ok(())
        }
        Err(e) => Err(Error::L2tp(e)),
    }
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
        let tunnels = RwLock::new(BTreeMap::new());
        Ok(Self { handle, tunnels })
    }

    pub(crate) async fn has_tunnel(&self, tunnel_id: u32) -> bool {
        self.tunnels.read().await.contains_key(&tunnel_id)
    }

    pub(crate) async fn has_interface(if_name: &L2tpIfName) -> Result<bool> {
        Ok(interface_index(if_name).await?.is_some())
    }

    pub(crate) async fn interface_name(index: u32) -> Result<Option<L2tpIfName>> {
        interface_name(index).await
    }

    pub(crate) async fn add_tunnel(
        &self,
        tunnel_id: u32,
        peer_tunnel_id: u32,
        remote_addr: IpAddr,
        if_name: Option<&L2tpIfName>,
    ) -> Result<()> {
        if self.has_tunnel(tunnel_id).await {
            return Err(Error::Other("Duplicate tunnel_id".to_string()));
        }

        let local = l2tp::IpEndpoint::v6(Ipv6Addr::UNSPECIFIED);
        let remote = l2tp::IpEndpoint::v6(to_ipv6_mapped(remote_addr));

        let config = l2tp::TunnelConfig::new(
            l2tp::TunnelId(tunnel_id),
            l2tp::TunnelId(peer_tunnel_id),
            l2tp::Encapsulation::Ip { local, remote },
        )
        .map_err(Error::L2tp)?;

        // Binds with tunnel_id and connects with peer_tunnel_id as the
        // L2TP/IP connection IDs; a missing device is reported as ENODEV.
        // The device's index is captured right away so that later operations
        // address the device by identity.
        let before = if_name
            .map(|name| name.index())
            .transpose()
            .map_err(Error::L2tp)?;
        let socket = l2tp::TunnelSocket::for_config(&config, if_name).map_err(Error::L2tp)?;
        let bound = match (if_name, before) {
            (Some(name), Some(before)) => {
                let after = name.index().map_err(Error::L2tp)?;
                if before != after {
                    return Err(Error::Other(format!(
                        "interface {name} changed identity (index {before} to {after}) while binding"
                    )));
                }
                Some(BoundDevice {
                    name: *name,
                    index: after,
                })
            }
            _ => None,
        };

        let mut handle = self
            .handle
            .create_tunnel(config, socket)
            .await
            .map_err(Error::L2tp)?;

        handle.set_auto_delete(false);

        let tunnel = TunnelState {
            remote_addr: RwLock::new(remote_addr),
            handle,
            bound_interface: RwLock::new(bound),
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

        let new_remote = l2tp::IpEndpoint::v6(to_ipv6_mapped(remote_addr));
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
        let mut bound_interface = tunnel.bound_interface.write().await;
        let socket = tunnel_socket(tunnel)?;

        // Disconnect to clear a stale source address and force source selection.
        // This also clears SO_BINDTODEVICE, which must be restored before connect.
        // The socket tracks its own connection state, so the disconnect has to
        // go through it rather than through a raw connect(AF_UNSPEC).
        socket.disconnect().map_err(Error::L2tp)?;

        // Re-bind to the same device by identity: its name may have changed,
        // and the configured name may by now belong to another device.
        if let Some(device) = bound_interface.as_ref() {
            *bound_interface = Some(rebind_socket_to_device(socket, device)?);
        }

        let remote = l2tp::IpEndpoint::v6(to_ipv6_mapped(*tunnel.remote_addr.read().await));
        tunnel.handle.reconnect_ip(&remote).map_err(Error::L2tp)?;

        let info = tunnel.handle.get().await.map_err(Error::L2tp)?;
        verify_reconnected_endpoint(
            tunnel_id,
            bound_interface.as_ref().map(|device| &device.name),
            &info.encapsulation,
        )
    }

    pub(crate) async fn bind_tunnel_interface(
        &self,
        tunnel_id: u32,
        if_name: &L2tpIfName,
    ) -> Result<()> {
        let tunnels = self.tunnels.read().await;
        let tunnel = tunnels
            .get(&tunnel_id)
            .ok_or_else(|| Error::Other("tunnel not found".to_string()))?;
        let mut bound_interface = tunnel.bound_interface.write().await;

        *bound_interface = Some(bind_socket_to_named_device(
            tunnel_socket(tunnel)?,
            if_name,
        )?);
        Ok(())
    }

    pub(crate) async fn bound_interface_index(&self, tunnel_id: u32) -> Option<u32> {
        let tunnels = self.tunnels.read().await;
        let tunnel = tunnels.get(&tunnel_id)?;
        let bound = tunnel.bound_interface.read().await;
        bound.map(|device| device.index)
    }

    /// Forgets the recorded binding. The kernel keeps the socket bound to
    /// the (gone or renamed) device until the next bind or disconnect.
    pub(crate) async fn forget_tunnel_binding(&self, tunnel_id: u32) {
        let tunnels = self.tunnels.read().await;
        if let Some(tunnel) = tunnels.get(&tunnel_id) {
            *tunnel.bound_interface.write().await = None;
        }
    }

    pub(crate) async fn delete_tunnel(&self, tunnel_id: u32) -> Result<()> {
        if !self.has_tunnel(tunnel_id).await {
            return Err(Error::Other(format!("Tunnel not found: {}", tunnel_id)));
        }

        let delete_result = deletion_result(
            &format!("tunnel_id={tunnel_id}"),
            self.handle.delete_tunnel(l2tp::TunnelId(tunnel_id)).await,
        );

        // Dropping the TunnelState closes the managed socket, which tears the
        // tunnel down even if the netlink deletion is still pending.
        let removed = {
            let mut tunnels = self.tunnels.write().await;
            remove_if_delete_succeeded(&mut tunnels, &tunnel_id, delete_result)?
        };
        if removed.is_none() {
            return Err(Error::Other(format!("Tunnel not found: {}", tunnel_id)));
        }

        Ok(())
    }

    async fn sessions_of(
        &self,
        tunnel_id: u32,
    ) -> Option<Arc<RwLock<BTreeMap<u32, SessionState>>>> {
        let tunnels = self.tunnels.read().await;
        tunnels.get(&tunnel_id).map(|t| Arc::clone(&t.sessions))
    }

    pub(crate) async fn has_session(&self, tunnel_id: u32, session_id: u32) -> bool {
        if let Some(sessions) = self.sessions_of(tunnel_id).await {
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
        if_name: &L2tpIfName,
        hwaddr: Option<&HwAddr>,
    ) -> Result<()> {
        if self.has_session(tunnel_id, session_id).await {
            return Err(Error::Other(format!(
                "Session exists: {}, tunnel: {}",
                session_id, tunnel_id
            )));
        }

        let sessions = self
            .sessions_of(tunnel_id)
            .await
            .ok_or_else(|| Error::Other(format!("No such tunnel: {}", tunnel_id)))?;

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
            ifname: Some(*if_name),
        };

        let mut handle = self
            .handle
            .create_session(config)
            .await
            .map_err(Error::L2tp)?;

        handle.set_auto_delete(false);

        // Until the session is recorded, every failure removes it again so
        // that nothing half-configured is left behind and reconcile retries.
        let prepared = async {
            let Some(index) = handle.ifindex() else {
                // Only if the registration notification was lost and the name
                // lookup failed too.
                return Err(Error::Other(format!(
                    "interface {if_name} of session {session_id} in tunnel {tunnel_id} cannot be identified"
                )));
            };
            let initial_hwaddr = link_hwaddr(&Rtnl::connect()?.get_link(index).await?);
            if let Some(hwaddr) = hwaddr {
                apply_hwaddr(index, *hwaddr).await?;
            }
            Ok((index, initial_hwaddr))
        }
        .await;

        let (index, initial_hwaddr) = match prepared {
            Ok(prepared) => prepared,
            Err(e) => {
                if let Err(cleanup) = handle.delete().await {
                    warn!(
                        "failed to remove session {} in tunnel {} after a setup failure: {}",
                        session_id, tunnel_id, cleanup
                    );
                }
                return Err(e);
            }
        };

        let session = SessionState {
            index,
            initial_hwaddr,
            handle,
        };

        sessions.write().await.insert(session_id, session);

        Ok(())
    }

    async fn session_device(
        &self,
        tunnel_id: u32,
        session_id: u32,
    ) -> Result<(u32, Option<HwAddr>)> {
        let not_found = || {
            Error::Other(format!(
                "No such session {} in tunnel {}",
                session_id, tunnel_id
            ))
        };
        let sessions = self.sessions_of(tunnel_id).await.ok_or_else(not_found)?;
        let sessions = sessions.read().await;
        let session = sessions.get(&session_id).ok_or_else(not_found)?;
        Ok((session.index, session.initial_hwaddr))
    }

    pub(crate) async fn modify_session(
        &self,
        tunnel_id: u32,
        session_id: u32,
        ifname: &L2tpIfName,
    ) -> Result<()> {
        let (index, _) = self.session_device(tunnel_id, session_id).await?;
        rename_interface(index, ifname).await
    }

    /// Sets the session device's hardware address, or restores the address
    /// the kernel assigned at creation when `hwaddr` is `None`.
    pub(crate) async fn set_session_hwaddr(
        &self,
        tunnel_id: u32,
        session_id: u32,
        hwaddr: Option<&HwAddr>,
    ) -> Result<()> {
        let (index, initial) = self.session_device(tunnel_id, session_id).await?;
        match hwaddr.copied().or(initial) {
            Some(target) => apply_hwaddr(index, target).await,
            // No configured address and no usable creation-time address.
            None => Ok(()),
        }
    }

    pub(crate) async fn delete_session(&self, tunnel_id: u32, session_id: u32) -> Result<()> {
        let not_found = || {
            Error::Other(format!(
                "No such session {} on tunnel {}",
                session_id, tunnel_id
            ))
        };
        let sessions = self.sessions_of(tunnel_id).await.ok_or_else(not_found)?;

        if !sessions.read().await.contains_key(&session_id) {
            return Err(not_found());
        }

        let delete_result = deletion_result(
            &format!("session_id={session_id} in tunnel_id={tunnel_id}"),
            self.handle
                .delete_session(l2tp::TunnelId(tunnel_id), l2tp::SessionId(session_id))
                .await,
        );

        let removed = {
            let mut sessions = sessions.write().await;
            remove_if_delete_succeeded(&mut sessions, &session_id, delete_result)?
        };
        if removed.is_none() {
            return Err(not_found());
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::{
        deletion_result, interface_index, remove_if_delete_succeeded, verify_reconnected_endpoint,
        State,
    };
    use crate::config::HwAddr;
    use l2tp::{Encapsulation, IpEndpoint, L2tpIfName, L2tpIfNameExt};
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::atomic::{AtomicU32, Ordering};

    fn ifname(name: &str) -> L2tpIfName {
        L2tpIfName::from_name(name).unwrap()
    }

    #[test]
    fn reconnect_verification_rejects_unspecified_local_endpoints() {
        let device = ifname("underlay0");
        for local in [
            IpEndpoint::V4(Ipv4Addr::UNSPECIFIED),
            IpEndpoint::v6(Ipv6Addr::UNSPECIFIED),
        ] {
            let remote = match local {
                IpEndpoint::V4(_) => IpEndpoint::V4(Ipv4Addr::LOCALHOST),
                IpEndpoint::V6 { .. } => IpEndpoint::v6(Ipv6Addr::LOCALHOST),
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
                assert!(
                    message.contains(device.map(|d| d.to_str().unwrap()).unwrap_or("<unbound>"))
                );
            }
        }
    }

    #[test]
    fn reconnect_verification_accepts_selected_local_endpoints() {
        for local in [
            IpEndpoint::V4(Ipv4Addr::LOCALHOST),
            IpEndpoint::v6(Ipv6Addr::LOCALHOST),
            IpEndpoint::v6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
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

    #[test]
    fn deletion_result_treats_acknowledged_deletions_as_complete() {
        deletion_result("x", Ok(())).unwrap();
        deletion_result("x", Err(l2tp::Error::DeletionPending(l2tp::TunnelId(7)))).unwrap();
        deletion_result(
            "x",
            Err(l2tp::Error::Io(std::io::Error::from_raw_os_error(
                libc::ENODEV,
            ))),
        )
        .unwrap();
        deletion_result(
            "x",
            Err(l2tp::Error::KernelError {
                code: libc::ENODEV,
                message: "No such device".to_string(),
            }),
        )
        .unwrap();
        assert!(deletion_result(
            "x",
            Err(l2tp::Error::Io(std::io::Error::from_raw_os_error(
                libc::EPERM
            ))),
        )
        .is_err());
    }

    #[tokio::test]
    async fn interface_index_resolves_loopback_and_reports_missing_names() {
        assert!(interface_index(&ifname("lo")).await.unwrap().is_some());
        assert_eq!(
            interface_index(&ifname("rsl2tp-missing")).await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn link_lookup_reads_loopback_without_privileges() {
        let rtnl = super::Rtnl::connect().unwrap();
        let index = ifname("lo").index().unwrap();
        let link = rtnl.get_link(index).await.unwrap();
        assert_eq!(super::link_name(&link), Some(ifname("lo")));
        // Loopback carries an all-zero address, which is not a usable one.
        assert_eq!(super::link_hwaddr(&link), None);
        assert!(rtnl.get_link(u32::MAX).await.is_err());
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
        let if_name = if_name.map(ifname);
        for _ in 0..16 {
            let id = 1_000_000_000
                + (std::process::id().wrapping_mul(32) + NEXT_ID.fetch_add(2, Ordering::Relaxed))
                    % 500_000_000;
            match state
                .add_tunnel(
                    id,
                    id + 1,
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                    if_name.as_ref(),
                )
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

    async fn bound_interface(state: &State, id: u32) -> Option<L2tpIfName> {
        let tunnels = state.tunnels.read().await;
        let bound = tunnels[&id].bound_interface.read().await;
        bound.map(|device| device.name)
    }

    async fn with_socket<R>(state: &State, id: u32, f: impl FnOnce(&l2tp::TunnelSocket) -> R) -> R {
        let tunnels = state.tunnels.read().await;
        f(tunnels[&id].handle.socket().unwrap())
    }

    async fn tunnel_info(state: &State, id: u32) -> l2tp::TunnelInfo {
        let tunnels = state.tunnels.read().await;
        tunnels[&id].handle.get().await.unwrap()
    }

    async fn set_remote(state: &State, id: u32, addr: IpAddr) {
        let tunnels = state.tunnels.read().await;
        *tunnels[&id].remote_addr.write().await = addr;
    }

    #[tokio::test]
    #[ignore = "requires CAP_NET_ADMIN/root and kernel IPv6 L2TP support"]
    async fn privileged_add_tunnel_records_bound_interface() {
        let Some((state, id)) = privileged_state(Some("lo")).await else {
            return;
        };
        assert_eq!(bound_interface(&state, id).await, Some(ifname("lo")));
        assert_eq!(
            state.bound_interface_index(id).await,
            Some(ifname("lo").index().unwrap())
        );
        assert_eq!(with_socket(&state, id, socket_bound_interface).await, "lo");
        state.forget_tunnel_binding(id).await;
        assert_eq!(state.bound_interface_index(id).await, None);
        state.delete_tunnel(id).await.unwrap();
    }

    #[tokio::test]
    async fn interface_name_resolves_loopback_and_reports_missing_indexes() {
        let index = ifname("lo").index().unwrap();
        assert_eq!(
            State::interface_name(index).await.unwrap(),
            Some(ifname("lo"))
        );
        assert_eq!(State::interface_name(u32::MAX).await.unwrap(), None);
    }

    #[tokio::test]
    #[ignore = "requires CAP_NET_ADMIN/root and kernel IPv6 L2TP support"]
    async fn privileged_add_tunnel_records_unbound_socket() {
        let Some((state, id)) = privileged_state(None).await else {
            return;
        };
        state.reconnect_tunnel(id).await.unwrap();
        assert!(bound_interface(&state, id).await.is_none());
        assert_eq!(with_socket(&state, id, socket_bound_interface).await, "");
        state.delete_tunnel(id).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires CAP_NET_ADMIN/root and kernel IPv6 L2TP support"]
    async fn privileged_bind_tunnel_interface_records_only_successful_binding() {
        let Some((state, id)) = privileged_state(None).await else {
            return;
        };
        let missing = ifname("l2tp-missing");
        assert!(missing.index().is_err());
        assert!(state.bind_tunnel_interface(id, &missing).await.is_err());
        assert!(bound_interface(&state, id).await.is_none());

        state
            .bind_tunnel_interface(id, &ifname("lo"))
            .await
            .unwrap();
        assert!(state.bind_tunnel_interface(id, &missing).await.is_err());
        // A late bind must also be restored on every subsequent reconnect.
        for _ in 0..3 {
            state.reconnect_tunnel(id).await.unwrap();
            assert_eq!(bound_interface(&state, id).await, Some(ifname("lo")));
            assert_eq!(with_socket(&state, id, socket_bound_interface).await, "lo");
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
            assert_eq!(with_socket(&state, id, socket_bound_interface).await, "lo");
            assert_eq!(
                tunnel_info(&state, id).await.encapsulation,
                Encapsulation::Ip {
                    local: IpEndpoint::v6(Ipv6Addr::LOCALHOST),
                    remote: IpEndpoint::v6(Ipv6Addr::LOCALHOST),
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
        // The isolated test namespace has only loopback, with no route here.
        set_remote(&state, id, "2001:db8::dead".parse().unwrap()).await;
        assert!(state.reconnect_tunnel(id).await.is_err());
        assert_eq!(bound_interface(&state, id).await, Some(ifname("lo")));
        assert_eq!(with_socket(&state, id, socket_bound_interface).await, "lo");

        set_remote(&state, id, IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
        state
            .reconnect_tunnel(id)
            .await
            .expect("retry with a reachable route");
        assert_eq!(with_socket(&state, id, socket_bound_interface).await, "lo");
        let Encapsulation::Ip { local, .. } = tunnel_info(&state, id).await.encapsulation else {
            panic!("expected IP encapsulation");
        };
        assert_eq!(local, IpEndpoint::v6(Ipv6Addr::LOCALHOST));
        state.delete_tunnel(id).await.unwrap();
    }

    async fn session_device(state: &State, id: u32, session_id: u32) -> (u32, Option<HwAddr>) {
        state.session_device(id, session_id).await.unwrap()
    }

    async fn session_info(state: &State, id: u32, session_id: u32) -> l2tp::SessionInfo {
        let tunnels = state.tunnels.read().await;
        let sessions = tunnels[&id].sessions.read().await;
        sessions[&session_id].handle.get().await.unwrap()
    }

    async fn current_hwaddr(index: u32) -> Option<HwAddr> {
        let rtnl = super::Rtnl::connect().unwrap();
        super::link_hwaddr(&rtnl.get_link(index).await.unwrap())
    }

    // Run twice in a row: the second run re-creates the session under the
    // same interface_name after delete_session, which exercises the
    // DeletionPending/ENODEV handling.
    #[tokio::test]
    #[ignore = "requires CAP_NET_ADMIN/root, l2tp_eth and kernel IPv6 L2TP support"]
    async fn privileged_modify_session_renames_by_index() {
        let Some((state, id)) = privileged_state(None).await else {
            return;
        };
        let session_id = id + 2;
        let created = ifname("rsl2tp-t0");
        let renamed = ifname("rsl2tp-t1");

        state
            .add_session(id, session_id, session_id, &created, None)
            .await
            .expect("create session");
        let (index, _) = session_device(&state, id, session_id).await;
        assert_eq!(interface_index(&created).await.unwrap(), Some(index));

        state
            .modify_session(id, session_id, &renamed)
            .await
            .expect("rename session interface");
        // A rename to the current name is a no-op, not an error.
        state
            .modify_session(id, session_id, &renamed)
            .await
            .expect("rename to the same name");

        assert_eq!(interface_index(&renamed).await.unwrap(), Some(index));
        assert_eq!(interface_index(&created).await.unwrap(), None);
        // The kernel keeps reporting the creation-time name.
        assert_eq!(
            session_info(&state, id, session_id).await.ifname,
            Some(created)
        );

        // Rename back and forth again to prove the index keeps working after
        // the kernel-reported name went stale.
        state
            .modify_session(id, session_id, &created)
            .await
            .expect("rename back");
        assert_eq!(interface_index(&created).await.unwrap(), Some(index));

        state.delete_session(id, session_id).await.unwrap();
        assert!(!state.has_session(id, session_id).await);
        state.delete_tunnel(id).await.unwrap();
        assert!(!state.has_tunnel(id).await);
    }

    #[tokio::test]
    #[ignore = "requires CAP_NET_ADMIN/root, l2tp_eth and kernel IPv6 L2TP support"]
    async fn privileged_session_hwaddr_is_applied_changed_and_restored() {
        let Some((state, id)) = privileged_state(None).await else {
            return;
        };
        let session_id = id + 2;
        let name = ifname("rsl2tp-t2");
        let first: HwAddr = "02:00:5e:00:53:01".parse().unwrap();
        let second: HwAddr = "02:00:5e:00:53:02".parse().unwrap();

        state
            .add_session(id, session_id, session_id, &name, Some(&first))
            .await
            .expect("create session with hardware address");
        let (index, initial) = session_device(&state, id, session_id).await;
        let initial = initial.expect("l2tpeth devices get a random address");
        assert_ne!(initial, first);
        assert_eq!(current_hwaddr(index).await, Some(first));

        // Changing the address while the device is up takes it down and up.
        let rtnl = super::Rtnl::connect().unwrap();
        rtnl.set_link(LinkUnspec::new_with_index(index).up().build())
            .await
            .expect("bring the device up");
        state
            .set_session_hwaddr(id, session_id, Some(&second))
            .await
            .expect("change the address of an up device");
        assert_eq!(current_hwaddr(index).await, Some(second));
        assert!(super::link_is_up(&rtnl.get_link(index).await.unwrap()));

        // Setting the current address again is a no-op.
        state
            .set_session_hwaddr(id, session_id, Some(&second))
            .await
            .unwrap();

        // Dropping the configured address restores the kernel's choice.
        state
            .set_session_hwaddr(id, session_id, None)
            .await
            .expect("restore the initial address");
        assert_eq!(current_hwaddr(index).await, Some(initial));

        state.delete_session(id, session_id).await.unwrap();
        state.delete_tunnel(id).await.unwrap();
    }

    use rtnetlink::LinkUnspec;

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
}
