//! Kernel-facing operations: tunnels, sessions and their devices.
//!
//! This module is private; [`crate::runtime::Runtime`] owns the only
//! instance and decides when each operation runs.

mod link_identity;

use crate::config::{Cookie, HwAddr, IpVersion, TunnelConfig};
use crate::error::{Error, Result};
use link_identity::{CreationWatch, LinkIdentity, LinkIdentityMonitor, LinkStatus};

use futures_util::{StreamExt, TryStreamExt};
use l2tp::{L2tpIfName, L2tpIfNameExt};
use log::{debug, info, warn};
use rtnetlink::packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_REQUEST};
use rtnetlink::packet_route::link::{
    InfoData, InfoKind, InfoVrf, LinkAttribute, LinkFlags, LinkInfo, LinkMessage,
};
use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute, RouteMessage};
use rtnetlink::packet_route::{AddressFamily, RouteNetlinkMessage};
use rtnetlink::{LinkDummy, LinkUnspec, RouteMessageBuilder};

use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;

use std::{
    collections::{BTreeMap, BTreeSet},
    hash::BuildHasher,
    net::{IpAddr, Ipv6Addr},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
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
        self.find_link(index)
            .await?
            .ok_or_else(|| Error::Other(format!("interface index {index} not found")))
    }

    async fn find_link(&self, index: u32) -> Result<Option<LinkMessage>> {
        let mut links = self.handle.link().get().match_index(index).execute();
        match links.try_next().await {
            Ok(link) => Ok(link),
            Err(e) if is_netlink_errno(&e, libc::ENODEV) || is_netlink_errno(&e, libc::ENXIO) => {
                Ok(None)
            }
            Err(e) => Err(Error::Other(format!(
                "failed to look up interface index {index}: {e}"
            ))),
        }
    }

    async fn set_link(&self, message: LinkMessage) -> std::result::Result<(), rtnetlink::Error> {
        self.handle.link().set(message).execute().await
    }

    /// Whether the kernel routes `destination` for a socket bound to the
    /// device `oif` (a VRF, say), or for an unbound one. The lookup is the
    /// one `connect` would do, so a reject route (blackhole, unreachable,
    /// prohibit) counts as no route: it refuses connections just the same.
    async fn routes(&self, destination: Ipv6Addr, oif: Option<u32>) -> Result<bool> {
        let mut message = RouteMessage::default();
        message.header.address_family = AddressFamily::Inet6;
        message.header.destination_prefix_length = 128;
        message
            .attributes
            .push(RouteAttribute::Destination(RouteAddress::Inet6(
                destination,
            )));
        if let Some(oif) = oif {
            message.attributes.push(RouteAttribute::Oif(oif));
        }
        let mut request = NetlinkMessage::from(RouteNetlinkMessage::GetRoute(message));
        request.header.flags = NLM_F_REQUEST;
        let mut handle = self.handle.clone();
        let mut responses = handle.request(request).map_err(|e| {
            Error::Other(format!("failed to look up the route to {destination}: {e}"))
        })?;
        while let Some(response) = responses.next().await {
            match response.payload {
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(_)) => return Ok(true),
                NetlinkPayload::Error(error) => {
                    let Some(code) = error.code else {
                        // An acknowledgement without a route.
                        return Ok(false);
                    };
                    return match code.get().unsigned_abs() as i32 {
                        libc::ENETUNREACH
                        | libc::EHOSTUNREACH
                        | libc::EINVAL
                        | libc::EACCES
                        | libc::EAGAIN => Ok(false),
                        _ => Err(Error::Other(format!(
                            "failed to look up the route to {destination}: {error}"
                        ))),
                    };
                }
                _ => {}
            }
        }
        Ok(false)
    }

    /// Test fixture for creating an existing route owned by another manager.
    #[cfg(test)]
    async fn route_to_device(&self, destination: Ipv6Addr, index: u32, table: u32) -> Result<()> {
        let message = RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(destination, 128)
            .output_interface(index)
            .table_id(table)
            .build();
        self.handle
            .route()
            .add(message)
            .replace()
            .execute()
            .await
            .map_err(|e| Error::Other(format!("failed to install test route: {e}")))
    }

    /// Adds only the daemon's discard route, preserving every existing route.
    /// Callers supply an owned null device and an explicitly tracked table.
    async fn install_discard_route(&self, index: u32, table: u32) -> Result<()> {
        let destination = TunnelConfig::NO_PEER_ADDR;
        let message = RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(destination, 128)
            .output_interface(index)
            .table_id(table)
            .build();
        let result = self.handle.route().add(message).execute().await;
        match result {
            Ok(()) => Ok(()),
            Err(e) if is_netlink_errno(&e, libc::EEXIST) => Ok(()),
            Err(e) => Err(Error::Other(format!(
                "failed to route {destination} to interface index {index} in table {table}: {e}"
            ))),
        }
    }
}

impl Drop for Rtnl {
    fn drop(&mut self) {
        self.connection.abort();
    }
}

#[async_trait::async_trait]
trait LinkOps: Sync {
    async fn get_link(&self, index: u32) -> Result<LinkMessage>;
    async fn set_link(&self, message: LinkMessage) -> std::result::Result<(), rtnetlink::Error>;
    async fn verify_identity(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl LinkOps for Rtnl {
    async fn get_link(&self, index: u32) -> Result<LinkMessage> {
        Rtnl::get_link(self, index).await
    }

    async fn set_link(&self, message: LinkMessage) -> std::result::Result<(), rtnetlink::Error> {
        Rtnl::set_link(self, message).await
    }
}

/// Device operations tied to the registration lifetime of one owned session.
/// A cached index alone may now refer to a replacement in this namespace.
struct SessionLinkOps<'a> {
    rtnl: Rtnl,
    monitor: &'a LinkIdentityMonitor,
    identity: &'a LinkIdentity,
}

impl<'a> SessionLinkOps<'a> {
    fn new(monitor: &'a LinkIdentityMonitor, identity: &'a LinkIdentity) -> Result<Self> {
        Ok(Self {
            rtnl: Rtnl::connect()?,
            monitor,
            identity,
        })
    }
}

#[async_trait::async_trait]
impl LinkOps for SessionLinkOps<'_> {
    async fn get_link(&self, index: u32) -> Result<LinkMessage> {
        if index != self.identity.index() {
            return Err(Error::Other(
                "session interface index does not match its ownership record".into(),
            ));
        }
        match self.monitor.validate(self.identity).await? {
            LinkStatus::Live(link) => Ok(link),
            LinkStatus::Invalidated => Err(Error::Other(format!(
                "session interface index {index} lost verifiable ownership continuity (device removal, namespace move, or missed link notifications)"
            ))),
        }
    }

    async fn set_link(&self, message: LinkMessage) -> std::result::Result<(), rtnetlink::Error> {
        self.rtnl.set_link(message).await
    }

    async fn verify_identity(&self) -> Result<()> {
        self.get_link(self.identity.index()).await.map(|_| ())
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

fn link_controller(link: &LinkMessage) -> Option<u32> {
    link.attributes.iter().find_map(|attr| match attr {
        LinkAttribute::Controller(index) if *index != 0 => Some(*index),
        _ => None,
    })
}

fn link_is_vrf(link: &LinkMessage) -> bool {
    link.attributes.iter().any(|attr| match attr {
        LinkAttribute::LinkInfo(info) => info
            .iter()
            .any(|info| matches!(info, LinkInfo::Kind(InfoKind::Vrf))),
        _ => false,
    })
}

fn link_is_dummy(link: &LinkMessage) -> bool {
    link.attributes.iter().any(|attr| match attr {
        LinkAttribute::LinkInfo(info) => info
            .iter()
            .any(|info| matches!(info, LinkInfo::Kind(InfoKind::Dummy))),
        _ => false,
    })
}

/// The routing table of a VRF device.
fn link_vrf_table(link: &LinkMessage) -> Option<u32> {
    link.attributes.iter().find_map(|attr| match attr {
        LinkAttribute::LinkInfo(info) => info.iter().find_map(|info| match info {
            LinkInfo::Data(InfoData::Vrf(vrf)) => vrf.iter().find_map(|attr| match attr {
                InfoVrf::TableId(table) => Some(*table),
                _ => None,
            }),
            _ => None,
        }),
        _ => None,
    })
}

/// The null device the daemon creates as a last resort, so that tunnels
/// without a peer can be connected to [`TunnelConfig::NO_PEER_ADDR`] on a
/// host that does not route it (an IPv4-only host, a VRF with an
/// unreachable default route) and their frames discarded. A `dummy` link
/// drops whatever it transmits: nothing is looped back, nothing leaves the
/// host, no neighbour discovery runs.
pub(crate) const NULL_DEVICE: &str = "rsl2tpnull0";

/// The configured name is published only after a new session's MAC is ready.
/// A bounded allocation loop handles collisions with any existing interfaces.
fn next_session_staging_name() -> Result<L2tpIfName> {
    static NEXT_NAME: AtomicUsize = AtomicUsize::new(0);
    let number = NEXT_NAME
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(std::process::id() as usize)
        & 0x00ff_ffff;
    L2tpIfName::from_name(format!("rsl2tp-t{number:06x}")).map_err(Error::L2tp)
}

/// The random MAC is installed atomically with creation. An index alone can be
/// reused after deletion, and a name can be assigned to somebody else's link.
struct NullDevice {
    // Creation is recorded before the subsequent lookup can fail. Cleanup
    // resolves the creation MAC by dumping links if that lookup never completed.
    index: Option<u32>,
    address: [u8; 6],
}

impl NullDevice {
    fn new() -> Self {
        static NEXT_DEVICE: AtomicUsize = AtomicUsize::new(0);
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let random = std::collections::hash_map::RandomState::new().hash_one((
            std::process::id(),
            time,
            NEXT_DEVICE.fetch_add(1, Ordering::Relaxed),
        ));
        let mut address = [0; 6];
        address.copy_from_slice(&random.to_ne_bytes()[..6]);
        // A locally administered unicast MAC, like the kernel's dummy default.
        address[0] = (address[0] & !1) | 2;
        Self {
            index: None,
            address,
        }
    }

    fn owns(&self, link: &LinkMessage) -> bool {
        link_is_dummy(link)
            && link
                .attributes
                .iter()
                .any(|attr| matches!(attr, LinkAttribute::Address(address) if address.as_slice() == self.address))
    }

    async fn find(&mut self, rtnl: &Rtnl) -> Result<Option<LinkMessage>> {
        if let Some(index) = self.index {
            return Ok(rtnl.find_link(index).await?.filter(|link| self.owns(link)));
        }
        let mut links = rtnl.handle.link().get().execute();
        while let Some(link) = links
            .try_next()
            .await
            .map_err(|e| Error::Other(format!("failed to find the created null device: {e}")))?
        {
            if self.owns(&link) {
                self.index = Some(link.header.index);
                return Ok(Some(link));
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DiscardRouteContext {
    Main,
    Vrf(L2tpIfName),
}

impl DiscardRouteContext {
    async fn from_vrf(rtnl: &Rtnl, vrf: Option<u32>) -> Result<Self> {
        let Some(index) = vrf else {
            return Ok(Self::Main);
        };
        let link = rtnl.get_link(index).await?;
        if !link_is_vrf(&link) || link_vrf_table(&link).is_none() {
            return Err(Error::Other(format!(
                "interface index {index} is not a VRF"
            )));
        }
        let name = link_name(&link)
            .ok_or_else(|| Error::Other(format!("VRF index {index} has no interface name")))?;
        Ok(Self::Vrf(name))
    }

    /// A VRF may be replaced with another index and routing table. Resolve
    /// its name immediately before installation, without falling back to main.
    async fn table(&self, rtnl: &Rtnl) -> Result<u32> {
        let Self::Vrf(name) = self else {
            return Ok(RT_TABLE_MAIN);
        };
        let index = interface_index(name)
            .await?
            .ok_or_else(|| Error::Other(format!("VRF {name} is missing")))?;
        let link = rtnl.get_link(index).await?;
        if link_name(&link).as_ref() != Some(name) || !link_is_vrf(&link) {
            return Err(Error::Other(format!(
                "interface {name} is no longer the requested VRF"
            )));
        }
        link_vrf_table(&link)
            .ok_or_else(|| Error::Other(format!("VRF {name} has no routing table")))
    }
}

#[derive(Default)]
struct DiscardResources {
    devices: Vec<NullDevice>,
    /// Fallbacks requested by this State, including an incomplete installation.
    routes: Vec<DiscardRouteContext>,
}

/// The main routing table.
const RT_TABLE_MAIN: u32 = 254;

fn is_netlink_errno(err: &rtnetlink::Error, errno: i32) -> bool {
    // The kernel reports negative errno values; compare magnitudes without
    // the overflow `abs` has at `i32::MIN`.
    matches!(err, rtnetlink::Error::NetlinkError(msg)
        if msg.raw_code().unsigned_abs() == errno.unsigned_abs())
}

/// Renames the interface with index `index` to `new`.
///
/// Devices are addressed by index because the kernel records a session's
/// interface name only once, at creation, so the name reported later never
/// follows a rename. A rename to the name the device already bears is a
/// no-op.
#[cfg(test)]
async fn rename_interface(index: u32, new: &L2tpIfName) -> Result<()> {
    let rtnl = Rtnl::connect()?;
    rename_interface_with(&rtnl, index, new).await
}

async fn rename_interface_with(rtnl: &impl LinkOps, index: u32, new: &L2tpIfName) -> Result<()> {
    let link = rtnl.get_link(index).await?;
    if link_name(&link).as_ref() == Some(new) {
        return Ok(());
    }

    let name = new
        .to_str()
        .map_err(|_| Error::Other(format!("non-UTF-8 interface name {new:?}")))?;
    rtnl.verify_identity().await?;
    rtnl.set_link(LinkUnspec::new_with_index(index).name(name).build())
        .await
        .map_err(|e| {
            Error::Other(format!(
                "failed to rename interface index {index} to {new}: {e}"
            ))
        })
}

/// The cookies of a session: the one appended to every frame it sends and
/// the one required in every frame it receives. `None` is no cookie, which
/// is the wire format of rs-l2tpd 0.1.x.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SessionCookies {
    pub(crate) cookie: Option<Cookie>,
    pub(crate) peer_cookie: Option<Cookie>,
}

impl SessionCookies {
    fn to_l2tp(cookie: Option<Cookie>) -> l2tp::Cookie {
        cookie.map_or_else(l2tp::Cookie::none, Cookie::to_l2tp)
    }
}

/// What became of a hardware address change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HwAddrApply {
    /// The device carries the address.
    Applied,
    /// The device is up, and an `l2tpeth` device only accepts a new address
    /// while it is down. The change is applied once the device is down.
    Deferred,
}

/// Sets the hardware address of the interface with index `index` to
/// `target` and verifies the result.
///
/// A running device is never taken down for this: on Linux that drops its
/// IPv6 addresses, its routes and its neighbour state, which would break
/// traffic the configuration never asked to interrupt. The change is
/// deferred instead and repeated when the device is seen down.
async fn apply_hwaddr_with(rtnl: &impl LinkOps, index: u32, target: HwAddr) -> Result<HwAddrApply> {
    let link = rtnl.get_link(index).await?;
    if link_hwaddr(&link) == Some(target) {
        return Ok(HwAddrApply::Applied);
    }
    if link_is_up(&link) {
        return Ok(HwAddrApply::Deferred);
    }

    let message = LinkUnspec::new_with_index(index)
        .address(target.octets().to_vec())
        .build();
    rtnl.verify_identity().await?;
    match rtnl.set_link(message).await {
        Ok(()) => {}
        // Brought up between the lookup and the change.
        Err(e) if is_netlink_errno(&e, libc::EBUSY) => return Ok(HwAddrApply::Deferred),
        Err(e) => {
            return Err(Error::Other(format!(
                "failed to set hardware address {target} on interface index {index}: {e}"
            )))
        }
    }

    let link = rtnl.get_link(index).await?;
    match link_hwaddr(&link) {
        Some(current) if current == target => Ok(HwAddrApply::Applied),
        current => Err(Error::Other(format!(
            "interface index {index} reports hardware address {} after setting {target}",
            current.map_or_else(|| "<none>".to_string(), |a| a.to_string())
        ))),
    }
}

/// Prepare a newly owned session without lowering it. A network manager may
/// already have attached children, including VLANs moved to another namespace,
/// before the temporary name is published. Lowering their parent would remove
/// their IPv6 configuration, which this daemon cannot safely restore.
async fn prepare_staged_session_with(
    rtnl: &impl LinkOps,
    index: u32,
    target: HwAddr,
    final_name: &L2tpIfName,
) -> Result<HwAddrApply> {
    let name = final_name
        .to_str()
        .map_err(|_| Error::Other(format!("non-UTF-8 interface name {final_name:?}")))?;
    let outcome = apply_hwaddr_with(rtnl, index, target).await?;
    // Publish even when an early manager activation deferred the MAC change.
    // Leave all flags to its policy; the normal pending-MAC path will finish
    // the address change if that device is subsequently observed down.
    rtnl.verify_identity().await?;
    rtnl.set_link(LinkUnspec::new_with_index(index).name(name).build())
        .await
        .map_err(|e| {
            Error::Other(format!(
                "failed to publish prepared session interface {final_name}: {e}"
            ))
        })?;
    Ok(outcome)
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

/// A configured device name and the index selected by its last successful
/// binding. Every subsequent binding resolves the configured name again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BoundDevice {
    pub(crate) name: L2tpIfName,
    pub(crate) index: u32,
    /// Whether the last binding is still usable for address-event matching.
    /// An invalid binding retains its configured name for the next attempt.
    valid: bool,
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
        valid: true,
    })
}

/// Re-binds the socket by its configured name, resolving the device just
/// before the bind. A replacement under the same name is accepted; a missing
/// name fails even if the previously bound device still exists under a new name.
fn rebind_socket_to_device(
    socket: &l2tp::TunnelSocket,
    device: &BoundDevice,
) -> Result<BoundDevice> {
    bind_socket_to_named_device(socket, &device.name)
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
    identity: LinkIdentity,
    /// The hardware address the kernel assigned at creation, restored when
    /// the configuration stops naming one.
    initial_hwaddr: Option<HwAddr>,
    /// The configured hardware address is not on the device yet: the last
    /// attempt was deferred (device up) or failed. Retried on every
    /// reconcile and whenever the device changes, until it is applied.
    hwaddr_pending: bool,
    // Keep session handle alive for the session lifecycle even when we don't call methods on it.
    #[allow(dead_code)]
    handle: l2tp::SessionHandle,
}

struct PendingSession {
    handle: l2tp::SessionHandle,
    creation: CreationWatch,
    identity: Option<LinkIdentity>,
    staged: bool,
    /// The desired creation-only parameters. Names and MACs can change while
    /// this same kernel session waits for publication.
    config: l2tp::SessionConfig,
    /// None until the first successful link lookup; Some(None) records that
    /// the original device carried no usable Ethernet address.
    initial_hwaddr: Option<Option<HwAddr>>,
}

impl PendingSession {
    fn matches_creation(&self, config: &l2tp::SessionConfig) -> bool {
        self.config.peer_session_id == config.peer_session_id
            && self.config.cookie == config.cookie
            && self.config.peer_cookie == config.peer_cookie
    }
}

pub(crate) struct TunnelState {
    remote_addr: RwLock<IpAddr>,
    handle: l2tp::TunnelHandle,
    // Last successfully applied device, retained across disconnects for retries.
    // The write lock serializes binding and the entire reconnect sequence.
    bound_interface: RwLock<Option<BoundDevice>>,
    /// False from the start of a reconnect until its successful completion,
    /// including failures to disconnect. An incomplete attempt whose retry
    /// was lost is repeated on the next reconcile. Written under the
    /// `bound_interface` lock.
    connected: AtomicBool,

    /// session_id to SessionState
    sessions: Arc<RwLock<BTreeMap<u32, SessionState>>>,
}

pub(crate) struct State {
    handle: l2tp::L2tpHandle,
    link_identities: LinkIdentityMonitor,

    /// tunnel_id to TunnelState
    tunnels: RwLock<BTreeMap<u32, TunnelState>>,
    /// Sessions created in the kernel whose preparation has not completed.
    /// Keep the same device across setup errors: another manager may already
    /// have attached children, even before its final name is published.
    pending_sessions: RwLock<BTreeMap<(u32, u32), PendingSession>>,
    /// Serializes fallback creation, route repair, and shutdown cleanup.
    discard_resources: Mutex<DiscardResources>,
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
            // IPv4 uses a dual-stack socket, so a failed source selection can
            // be reported as ::ffff:0.0.0.0 rather than the IPv6 wildcard.
            if !local.ip().to_canonical().is_unspecified() {
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

/// Deletion borrows each handle's owner; an error must not consume it.
#[cfg(test)]
async fn cleanup_pending_entries<K, V, F, Fut>(
    entries: &mut BTreeMap<K, V>,
    mut delete: F,
) -> Result<()>
where
    K: Copy + Ord,
    F: FnMut(K) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let keys: Vec<_> = entries.keys().copied().collect();
    for key in keys {
        delete(key).await?;
        entries.remove(&key);
    }
    Ok(())
}

impl State {
    pub(crate) async fn new() -> Result<Self> {
        let handle = l2tp::L2tpHandle::new().await.map_err(Error::L2tp)?;
        let link_identities = LinkIdentityMonitor::new().await?;
        let tunnels = RwLock::new(BTreeMap::new());
        Ok(Self {
            handle,
            link_identities,
            tunnels,
            pending_sessions: RwLock::new(BTreeMap::new()),
            discard_resources: Mutex::new(DiscardResources::default()),
        })
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

    /// Validates a controller index captured before a slave disappeared.
    pub(crate) async fn interface_is_vrf(index: u32) -> Result<bool> {
        let rtnl = Rtnl::connect()?;
        Ok(rtnl
            .find_link(index)
            .await?
            .as_ref()
            .is_some_and(link_is_vrf))
    }

    /// Finds the VRF currently controlling the interface with `index`.
    ///
    /// Other controllers, such as bridges and bonds, do not select a VRF
    /// routing table. A deleted interface or controller has no current VRF.
    pub(crate) async fn interface_vrf_master(index: u32) -> Result<Option<u32>> {
        let rtnl = Rtnl::connect()?;
        let Some(link) = rtnl.find_link(index).await? else {
            return Ok(None);
        };
        let Some(controller) = link_controller(&link) else {
            return Ok(None);
        };
        let Some(master) = rtnl.find_link(controller).await? else {
            return Ok(None);
        };
        Ok(link_is_vrf(&master).then_some(controller))
    }

    pub(crate) async fn interface_index(if_name: &L2tpIfName) -> Result<Option<u32>> {
        interface_index(if_name).await
    }

    /// Whether a socket bound to the VRF with index `vrf`, or an unbound
    /// one, can be connected to [`TunnelConfig::NO_PEER_ADDR`]: the kernel
    /// routes it, and not through a reject route.
    pub(crate) async fn discard_route_exists(vrf: Option<u32>) -> Result<bool> {
        Rtnl::connect()?
            .routes(TunnelConfig::NO_PEER_ADDR, vrf)
            .await
    }

    /// Routes [`TunnelConfig::NO_PEER_ADDR`] to an owned null device,
    /// creating it or bringing it up as needed, in the
    /// table of the VRF with index `vrf` or the main one: the last resort
    /// for a host that does not route the address itself. Existing routes,
    /// including reject routes, are always preserved.
    pub(crate) async fn route_discard_to_null_device(&self, vrf: Option<u32>) -> Result<()> {
        let mut resources = self.discard_resources.lock().await;
        let rtnl = Rtnl::connect()?;
        let context = DiscardRouteContext::from_vrf(&rtnl, vrf).await?;
        if !resources.routes.contains(&context) {
            resources.routes.push(context);
        }
        let index = Self::null_device(&rtnl, &mut resources.devices).await?;
        let table = context.table(&rtnl).await?;
        rtnl.install_discard_route(index, table).await
    }

    /// Repairs only previously requested fallback routes. Existing routes are
    /// preserved, and every recorded VRF is resolved by its current name/table.
    /// A missing VRF remains pending without blocking repairs in other tables.
    pub(crate) async fn restore_discard_routes(&self) -> Result<()> {
        let mut resources = self.discard_resources.lock().await;
        if resources.routes.is_empty() {
            return Ok(());
        }
        let rtnl = Rtnl::connect()?;
        let mut first_error = None;
        for context in resources.routes.clone() {
            let restored = async {
                let index = Self::null_device(&rtnl, &mut resources.devices).await?;
                let table = context.table(&rtnl).await?;
                rtnl.install_discard_route(index, table).await
            }
            .await;
            if let Err(error) = restored {
                first_error.get_or_insert(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Reuses a verified owned link, or allocates an unused name. Existing
    /// devices are neither adopted nor changed, even if they are dummies.
    async fn null_device(rtnl: &Rtnl, devices: &mut Vec<NullDevice>) -> Result<u32> {
        for device in devices.iter_mut() {
            if let Some(link) = device.find(rtnl).await? {
                let index = link.header.index;
                if !link_is_up(&link) {
                    rtnl.set_link(LinkUnspec::new_with_index(index).up().build())
                        .await
                        .map_err(|e| {
                            Error::Other(format!(
                                "failed to bring the null device at index {index} up: {e}"
                            ))
                        })?;
                }
                return Ok(index);
            }
        }
        // All generated names fit Linux's 15-byte interface name limit.
        for suffix in 0..=99_999 {
            let name = if suffix == 0 {
                NULL_DEVICE.to_string()
            } else {
                format!("rsl2tpnull{suffix}")
            };
            let device = NullDevice::new();
            // Linux applies the MAC in RTM_NEWLINK, whereas IFLA_IFALIAS
            // can be silently ignored until a later RTM_SETLINK request.
            let message = LinkDummy::new(&name)
                .address(device.address.to_vec())
                .up()
                .build();
            match rtnl.handle.link().add(message).execute().await {
                Ok(()) => {}
                Err(e) if is_netlink_errno(&e, libc::EEXIST) => continue,
                Err(e) => {
                    return Err(Error::Other(format!(
                        "failed to create the null device {name}: {e}"
                    )))
                }
            }
            devices.push(device);
            let created = devices.last_mut().unwrap();
            let link = created.find(rtnl).await?.ok_or_else(|| {
                Error::Other(format!("the created null device {name} disappeared"))
            })?;
            info!("created null device {name} at index {}", link.header.index);
            return Ok(link.header.index);
        }
        Err(Error::Other(
            "no unused null device name is available".to_string(),
        ))
    }

    /// Removes only verified owned null devices, and with them their routes.
    /// Renames are harmless; a deleted device's replacement is never owned.
    pub(crate) async fn remove_null_device(&self) -> Result<()> {
        let mut resources = self.discard_resources.lock().await;
        // Clear intent first, including when deleting a device later fails.
        // A queued repair after shutdown must not recreate links or routes.
        resources.routes.clear();
        if resources.devices.is_empty() {
            return Ok(());
        }
        let rtnl = Rtnl::connect()?;
        while let Some(device) = resources.devices.last_mut() {
            if let Some(link) = device.find(&rtnl).await? {
                let index = link.header.index;
                match rtnl.handle.link().del(index).execute().await {
                    Ok(()) => {}
                    Err(e) if is_netlink_errno(&e, libc::ENODEV) => {}
                    Err(e) => {
                        return Err(Error::Other(format!(
                            "failed to remove the null device at index {index}: {e}"
                        )))
                    }
                }
                info!(
                    "removed owned null device {} at index {index}",
                    link_name(&link)
                        .map(|name| name.to_string())
                        .unwrap_or_default()
                );
            }
            resources.devices.pop();
        }
        Ok(())
    }

    /// The peer the tunnel is connected to now.
    pub(crate) async fn tunnel_remote_addr(&self, tunnel_id: u32) -> Option<IpAddr> {
        let tunnels = self.tunnels.read().await;
        let tunnel = tunnels.get(&tunnel_id)?;
        let remote_addr = *tunnel.remote_addr.read().await;
        Some(remote_addr)
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
        // Capture the device index for address events; every subsequent
        // binding resolves this configured name again.
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
                    valid: true,
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
            connected: AtomicBool::new(true),
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

        let previous_remote = *tunnel.remote_addr.read().await;
        if previous_remote == remote_addr {
            return Ok(());
        }

        let binding_changed = {
            let bound = tunnel.bound_interface.read().await;
            match bound.as_ref() {
                Some(device) => {
                    !device.valid || device.name.index().map_err(Error::L2tp)? != device.index
                }
                None => false,
            }
        };
        if !tunnel.connected.load(Ordering::Acquire)
            || binding_changed
            || previous_remote == IpAddr::V6(TunnelConfig::NO_PEER_ADDR)
            || previous_remote.to_canonical().is_ipv4() != remote_addr.to_canonical().is_ipv4()
        {
            // A dual-stack socket retains its selected source across connect.
            // Clear it when leaving the discard peer, crossing families or
            // changing devices, restoring the binding that disconnect clears.
            // A discard socket may still carry a removed address or the null
            // device's link-local source. Resolve a replacement even if its
            // link notification has not yet reached the runtime.
            if let Err(error) = Self::reconnect_tunnel_to(tunnel_id, tunnel, remote_addr).await {
                // The candidate endpoint is not applied. Preserve the old
                // connection when possible while the runtime retries it.
                if !tunnel.connected.load(Ordering::Acquire) {
                    if let Err(rollback) =
                        Self::reconnect_tunnel_to(tunnel_id, tunnel, previous_remote).await
                    {
                        warn!("failed to restore tunnel_id={tunnel_id} after peer update failed: {rollback}");
                    }
                }
                return Err(error);
            }
        } else {
            let new_remote = l2tp::IpEndpoint::v6(to_ipv6_mapped(remote_addr));
            tunnel
                .handle
                .reconnect_ip(&new_remote)
                .map_err(Error::L2tp)?;
        }

        *tunnel.remote_addr.write().await = remote_addr;

        Ok(())
    }

    pub(crate) async fn reconnect_tunnel(&self, tunnel_id: u32) -> Result<()> {
        let tunnels = self.tunnels.read().await;
        let tunnel = tunnels
            .get(&tunnel_id)
            .ok_or_else(|| Error::Other("tunnel not found".to_string()))?;
        let remote_addr = *tunnel.remote_addr.read().await;
        Self::reconnect_tunnel_to(tunnel_id, tunnel, remote_addr).await
    }

    async fn reconnect_tunnel_to(
        tunnel_id: u32,
        tunnel: &TunnelState,
        remote_addr: IpAddr,
    ) -> Result<()> {
        let mut bound_interface = tunnel.bound_interface.write().await;
        let socket = tunnel_socket(tunnel)?;

        // A missing configured name leaves this attempt incomplete, even
        // when the previous connection still works. Check before disconnect
        // so that waiting for a replacement does not strip that old binding.
        tunnel.connected.store(false, Ordering::Release);
        if let Some(device) = bound_interface.as_ref() {
            device.name.index().map_err(Error::L2tp)?;
        }

        // Disconnect to clear a stale source address and force source selection.
        // This also clears SO_BINDTODEVICE, which must be restored before connect.
        // The socket tracks its own connection state, so the disconnect has to
        // go through it rather than through a raw connect(AF_UNSPEC).
        socket.disconnect().map_err(Error::L2tp)?;

        // Resolve the configured name immediately before binding. The old
        // device may have been renamed or replaced since the previous bind.
        if let Some(device) = bound_interface.as_ref() {
            *bound_interface = Some(rebind_socket_to_device(socket, device)?);
        }

        let remote = l2tp::IpEndpoint::v6(to_ipv6_mapped(remote_addr));
        tunnel.handle.reconnect_ip(&remote).map_err(Error::L2tp)?;

        let info = tunnel.handle.get().await.map_err(Error::L2tp)?;
        verify_reconnected_endpoint(
            tunnel_id,
            bound_interface.as_ref().map(|device| &device.name),
            &info.encapsulation,
        )?;
        tunnel.connected.store(true, Ordering::Release);
        Ok(())
    }

    /// Whether this daemon's last reconnect completed successfully.
    /// A failed disconnect also leaves the attempt incomplete even if the
    /// socket still has its old peer. An unknown tunnel counts as connected.
    pub(crate) async fn tunnel_is_connected(&self, tunnel_id: u32) -> bool {
        let tunnels = self.tunnels.read().await;
        tunnels
            .get(&tunnel_id)
            .is_none_or(|tunnel| tunnel.connected.load(Ordering::Acquire))
    }

    /// The currently applied peer's address family, including the temporary
    /// discard peer used before DNS resolution. IPv4-mapped IPv6 peers use
    /// IPv4 on the underlay regardless of the configured family.
    pub(crate) async fn tunnel_ip_version(&self, tunnel_id: u32) -> Option<IpVersion> {
        let tunnels = self.tunnels.read().await;
        let tunnel = tunnels.get(&tunnel_id)?;
        let remote = *tunnel.remote_addr.read().await;
        Some(match remote.to_canonical() {
            IpAddr::V4(_) => IpVersion::V4,
            IpAddr::V6(_) => IpVersion::V6,
        })
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
        bound
            .filter(|device| device.valid)
            .map(|device| device.index)
    }

    /// Invalidates the recorded index while retaining the configured name
    /// for the next bind. The kernel keeps the socket bound to the old
    /// device until the next bind or disconnect; a missing name must not
    /// cause a later reconnect to silently use an unbound socket.
    pub(crate) async fn forget_tunnel_binding(&self, tunnel_id: u32) {
        let tunnels = self.tunnels.read().await;
        if let Some(tunnel) = tunnels.get(&tunnel_id) {
            let mut bound = tunnel.bound_interface.write().await;
            if let Some(device) = bound.as_mut() {
                device.valid = false;
            }
        }
    }

    pub(crate) async fn delete_tunnel(&self, tunnel_id: u32) -> Result<()> {
        // Closing our managed socket removes only its own kernel tunnel.
        // An ID-only TUNNEL_DELETE could instead remove a foreign replacement
        // if another administrator already deleted and reused this ID.
        let removed = {
            let mut tunnels = self.tunnels.write().await;
            let tunnel = tunnels
                .get(&tunnel_id)
                .ok_or_else(|| Error::Other(format!("Tunnel not found: {tunnel_id}")))?;
            tunnel_socket(tunnel)?;
            tunnels.remove(&tunnel_id)
        };
        drop(removed);

        self.pending_sessions
            .write()
            .await
            .retain(|(parent, _), _| *parent != tunnel_id);

        Ok(())
    }

    /// Remove only incomplete sessions no longer requested by the caller.
    /// Still-desired sessions retain their devices and children for retry.
    pub(crate) async fn retain_pending_sessions(
        &self,
        desired: &BTreeSet<(u32, u32)>,
    ) -> Result<()> {
        let mut pending = self.pending_sessions.write().await;
        let removed: Vec<_> = pending
            .keys()
            .filter(|key| !desired.contains(key))
            .copied()
            .collect();
        for key in removed {
            self.delete_pending_session(&pending[&key]).await?;
            pending.remove(&key);
        }
        Ok(())
    }

    async fn delete_pending_session(&self, session: &PendingSession) -> Result<()> {
        let identity = match &session.identity {
            Some(identity) => identity.clone(),
            None => match self
                .link_identities
                .finish_creation(&session.creation, session.handle.ifindex())
                .await
            {
                Ok(identity) => identity,
                Err(_) if session.creation.is_invalidated() => {
                    warn!("forgetting an incomplete session whose device ownership was lost");
                    return Ok(());
                }
                Err(error) => return Err(error),
            },
        };
        if matches!(
            self.link_identities.validate(&identity).await?,
            LinkStatus::Invalidated
        ) {
            warn!("forgetting incomplete session_id={} in tunnel_id={} because its device lifetime could not be verified; its IDs may have been reused",
                session.config.session_id.0, session.config.tunnel_id.0);
            return Ok(());
        }
        deletion_result(
            &format!(
                "incomplete session_id={} in tunnel_id={}",
                session.config.session_id.0, session.config.tunnel_id.0
            ),
            self.handle
                .delete_session(session.config.tunnel_id, session.config.session_id)
                .await,
        )
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
        cookies: SessionCookies,
    ) -> Result<HwAddrApply> {
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
            cookie: SessionCookies::to_l2tp(cookies.cookie),
            peer_cookie: SessionCookies::to_l2tp(cookies.peer_cookie),
            recv_seq: false,
            send_seq: false,
            lns_mode: false,
            recv_timeout_ms: None,
            ifname: Some(*if_name),
        };

        let key = (tunnel_id, session_id);
        // Keep an incomplete session through retries. Publication failures
        // must not tear down children which another manager already created.
        let mut pending = self.pending_sessions.write().await;
        if pending
            .get(&key)
            .is_some_and(|session| !session.matches_creation(&config))
        {
            self.delete_pending_session(&pending[&key]).await?;
            pending.remove(&key);
        }
        if let std::collections::btree_map::Entry::Vacant(entry) = pending.entry(key) {
            // There is no cancellation point between receiving the handle
            // and retaining ownership in the map.
            let (handle, creation) = self
                .create_session_handle(config.clone(), hwaddr.is_some())
                .await?;
            entry.insert(PendingSession {
                handle,
                creation,
                identity: None,
                staged: hwaddr.is_some(),
                config,
                initial_hwaddr: None,
            });
        }
        let session = pending.get_mut(&key).expect("pending session exists");
        if session.identity.is_none() {
            session.identity = Some(
                self.link_identities
                    .finish_creation(&session.creation, session.handle.ifindex())
                    .await?,
            );
        }
        let identity = session
            .identity
            .as_ref()
            .expect("session identity was captured");
        let index = identity.index();
        let rtnl = SessionLinkOps::new(&self.link_identities, identity)?;
        if session.initial_hwaddr.is_none() {
            session.initial_hwaddr = Some(link_hwaddr(&rtnl.get_link(index).await?));
        }
        let initial_hwaddr = session.initial_hwaddr.flatten();
        let target = hwaddr
            .copied()
            .or_else(|| session.staged.then_some(initial_hwaddr).flatten());
        let outcome = if let Some(target) = target {
            prepare_staged_session_with(&rtnl, index, target, if_name).await?
        } else {
            if session.staged || session.config.ifname.as_ref() != Some(if_name) {
                rename_interface_with(&rtnl, index, if_name).await?;
            }
            HwAddrApply::Applied
        };

        // Acquire the destination lock before taking ownership out of pending.
        let mut sessions = sessions.write().await;
        let pending = pending.remove(&key).expect("pending session exists");

        let session = SessionState {
            index,
            identity: pending.identity.expect("session identity was captured"),
            initial_hwaddr,
            hwaddr_pending: outcome == HwAddrApply::Deferred,
            handle: pending.handle,
        };

        sessions.insert(session_id, session);

        Ok(outcome)
    }

    async fn create_session_handle(
        &self,
        mut config: l2tp::SessionConfig,
        stage: bool,
    ) -> Result<(l2tp::SessionHandle, CreationWatch)> {
        if !stage {
            let creation = self
                .link_identities
                .arm_creation(
                    config
                        .ifname
                        .as_ref()
                        .expect("session creation always names its device"),
                )
                .await?;
            let mut handle = self
                .handle
                .create_session(config)
                .await
                .map_err(Error::L2tp)?;
            handle.set_auto_delete(false);
            return Ok((handle, creation));
        }
        let final_name = config.ifname;
        for _ in 0..32 {
            let name = next_session_staging_name()?;
            if Some(name) == final_name {
                continue;
            }
            config.ifname = Some(name);
            let creation = self.link_identities.arm_creation(&name).await?;
            match self.handle.create_session(config.clone()).await {
                Ok(mut handle) => {
                    handle.set_auto_delete(false);
                    return Ok((handle, creation));
                }
                Err(error)
                    if error.raw_os_error() == Some(libc::EEXIST)
                        && interface_index(&name).await?.is_some() => {}
                Err(error) => return Err(Error::L2tp(error)),
            }
        }
        Err(Error::Other(
            "could not allocate a temporary session interface name".to_string(),
        ))
    }

    #[cfg(test)]
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
        SessionLinkOps::new(&self.link_identities, &session.identity)?
            .verify_identity()
            .await?;
        Ok((session.index, session.initial_hwaddr))
    }

    pub(crate) async fn modify_session(
        &self,
        tunnel_id: u32,
        session_id: u32,
        ifname: &L2tpIfName,
    ) -> Result<()> {
        let sessions = self
            .sessions_of(tunnel_id)
            .await
            .ok_or_else(|| Error::Other(format!("No such tunnel: {tunnel_id}")))?;
        let sessions = sessions.read().await;
        let session = sessions.get(&session_id).ok_or_else(|| {
            Error::Other(format!(
                "No such session {session_id} in tunnel {tunnel_id}"
            ))
        })?;
        let rtnl = SessionLinkOps::new(&self.link_identities, &session.identity)?;
        rename_interface_with(&rtnl, session.index, ifname).await
    }

    /// Whether the session's configured hardware address still has to be
    /// applied (deferred while the device is up, or failed).
    pub(crate) async fn session_hwaddr_pending(&self, tunnel_id: u32, session_id: u32) -> bool {
        let Some(sessions) = self.sessions_of(tunnel_id).await else {
            return false;
        };
        let sessions = sessions.read().await;
        sessions
            .get(&session_id)
            .is_some_and(|session| session.hwaddr_pending)
    }

    /// Sets the session device's hardware address, or restores the address
    /// the kernel assigned at creation when `hwaddr` is `None`. A running
    /// device is left alone and the change is reported as deferred.
    pub(crate) async fn set_session_hwaddr(
        &self,
        tunnel_id: u32,
        session_id: u32,
        hwaddr: Option<&HwAddr>,
    ) -> Result<HwAddrApply> {
        let sessions = self
            .sessions_of(tunnel_id)
            .await
            .ok_or_else(|| Error::Other(format!("No such tunnel: {tunnel_id}")))?;
        let mut sessions = sessions.write().await;
        let session = sessions.get_mut(&session_id).ok_or_else(|| {
            Error::Other(format!(
                "No such session {session_id} in tunnel {tunnel_id}"
            ))
        })?;
        session.hwaddr_pending = true;
        let result = match hwaddr.copied().or(session.initial_hwaddr) {
            Some(target) => {
                let rtnl = SessionLinkOps::new(&self.link_identities, &session.identity)?;
                apply_hwaddr_with(&rtnl, session.index, target).await
            }
            // No configured address and no usable creation-time address.
            None => Ok(HwAddrApply::Applied),
        };
        if matches!(result, Ok(HwAddrApply::Applied)) {
            session.hwaddr_pending = false;
        }
        result
    }

    pub(crate) async fn delete_session(&self, tunnel_id: u32, session_id: u32) -> Result<()> {
        let not_found = || {
            Error::Other(format!(
                "No such session {} on tunnel {}",
                session_id, tunnel_id
            ))
        };
        let sessions = self.sessions_of(tunnel_id).await.ok_or_else(not_found)?;

        let identity = sessions
            .read()
            .await
            .get(&session_id)
            .ok_or_else(not_found)?
            .identity
            .clone();

        if matches!(
            self.link_identities.validate(&identity).await?,
            LinkStatus::Invalidated
        ) {
            warn!("forgetting session_id={session_id} in tunnel_id={tunnel_id} because its device lifetime could not be verified; its IDs may have been reused");
            sessions.write().await.remove(&session_id);
            return Ok(());
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
        SessionCookies, State,
    };
    use crate::config::{Cookie, HwAddr};
    use futures_util::TryStreamExt;
    use l2tp::{Encapsulation, IpEndpoint, L2tpIfName, L2tpIfNameExt};
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    struct MockLink {
        link: super::LinkMessage,
        fail_address: usize,
        set_requests: usize,
        activate_before_address: usize,
        activate_after_address: bool,
        publish_error: Option<i32>,
    }

    fn netlink_error(code: i32) -> rtnetlink::Error {
        let mut error = rtnetlink::packet_core::ErrorMessage::default();
        error.code = std::num::NonZeroI32::new(-code);
        rtnetlink::Error::NetlinkError(error)
    }

    #[test]
    fn vrf_classification_does_not_treat_other_controllers_or_ports_as_vrfs() {
        use super::{InfoKind, LinkAttribute, LinkInfo, LinkMessage};
        use rtnetlink::packet_route::link::InfoPortKind;

        let mut link = LinkMessage::default();
        assert_eq!(super::link_controller(&link), None);
        assert!(!super::link_is_vrf(&link));
        link.attributes.push(LinkAttribute::Controller(0));
        assert_eq!(super::link_controller(&link), None);
        link.attributes.push(LinkAttribute::Controller(42));
        assert_eq!(super::link_controller(&link), Some(42));

        for kind in [InfoKind::Bridge, InfoKind::Bond, InfoKind::Dummy] {
            link.attributes = vec![LinkAttribute::LinkInfo(vec![LinkInfo::Kind(kind)])];
            assert!(!super::link_is_vrf(&link));
        }
        link.attributes = vec![LinkAttribute::LinkInfo(vec![LinkInfo::PortKind(
            InfoPortKind::Vrf,
        )])];
        assert!(!super::link_is_vrf(&link));
        link.attributes = vec![LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Vrf)])];
        assert!(super::link_is_vrf(&link));
    }

    #[async_trait::async_trait]
    impl super::LinkOps for Mutex<MockLink> {
        async fn get_link(&self, _index: u32) -> crate::Result<super::LinkMessage> {
            Ok(self.lock().unwrap().link.clone())
        }

        async fn set_link(
            &self,
            message: super::LinkMessage,
        ) -> std::result::Result<(), rtnetlink::Error> {
            let mut state = self.lock().unwrap();
            state.set_requests += 1;
            if let Some(address) = message.attributes.iter().find_map(|attr| match attr {
                super::LinkAttribute::Address(address) => Some(address.clone()),
                _ => None,
            }) {
                if state.activate_before_address > 0 {
                    state.activate_before_address -= 1;
                    state.link.header.flags.insert(super::LinkFlags::Up);
                }
                if super::link_is_up(&state.link) {
                    return Err(netlink_error(libc::EBUSY));
                }
                if state.fail_address > 0 {
                    state.fail_address -= 1;
                    return Err(netlink_error(libc::ENOMEM));
                }
                state
                    .link
                    .attributes
                    .retain(|attr| !matches!(attr, super::LinkAttribute::Address(_)));
                state
                    .link
                    .attributes
                    .push(super::LinkAttribute::Address(address));
                if state.activate_after_address {
                    state.link.header.flags.insert(super::LinkFlags::Up);
                }
                return Ok(());
            }
            if let Some(name) = super::link_name(&message) {
                if let Some(errno) = state.publish_error {
                    return Err(netlink_error(errno));
                }
                state
                    .link
                    .attributes
                    .retain(|attr| !matches!(attr, super::LinkAttribute::IfName(_)));
                state.link.attributes.push(super::LinkAttribute::IfName(
                    name.to_str().unwrap().to_string(),
                ));
            }
            if message.header.change_mask.contains(super::LinkFlags::Up) {
                state
                    .link
                    .header
                    .flags
                    .set(super::LinkFlags::Up, super::link_is_up(&message));
            }
            Ok(())
        }
    }

    fn mock_link(up: bool, fail_address: usize) -> Mutex<MockLink> {
        let mut link = super::LinkMessage::default();
        if up {
            link.header.flags.insert(super::LinkFlags::Up);
        }
        link.attributes
            .push(super::LinkAttribute::Address(vec![2, 0, 0, 0, 0, 1]));
        link.attributes
            .push(super::LinkAttribute::IfName("staged0".to_string()));
        Mutex::new(MockLink {
            link,
            fail_address,
            set_requests: 0,
            activate_before_address: 0,
            activate_after_address: false,
            publish_error: None,
        })
    }

    #[tokio::test]
    async fn staged_session_preserves_activation_before_or_after_mac_change() {
        let target = "02:00:00:00:00:02".parse().unwrap();
        let original = "02:00:00:00:00:01".parse().unwrap();
        let final_name = ifname("pseudowire0");
        for (initial_up, before, after) in [(true, 0, false), (false, 1, false), (false, 0, true)] {
            let link = mock_link(initial_up, 0);
            {
                let mut state = link.lock().unwrap();
                state.activate_before_address = before;
                state.activate_after_address = after;
            }
            let outcome = super::prepare_staged_session_with(&link, 1, target, &final_name)
                .await
                .unwrap();
            let state = link.lock().unwrap();
            assert_eq!(super::link_name(&state.link), Some(final_name));
            let deferred = initial_up || before > 0;
            assert_eq!(
                outcome,
                if deferred {
                    super::HwAddrApply::Deferred
                } else {
                    super::HwAddrApply::Applied
                }
            );
            assert_eq!(
                super::link_hwaddr(&state.link),
                Some(if deferred { original } else { target })
            );
            assert!(
                super::link_is_up(&state.link),
                "the manager's activation must remain untouched"
            );
            assert_eq!(state.set_requests, if initial_up { 1 } else { 2 });
        }
    }

    #[tokio::test]
    async fn staged_session_reports_setup_errors_without_lowering_the_device() {
        let target = "02:00:00:00:00:02".parse().unwrap();
        let final_name = ifname("pseudowire0");
        let link = mock_link(false, 1);
        assert!(
            super::prepare_staged_session_with(&link, 1, target, &final_name)
                .await
                .is_err()
        );
        assert_eq!(
            super::link_name(&link.lock().unwrap().link),
            Some(ifname("staged0"))
        );

        let link = mock_link(true, 0);
        link.lock().unwrap().publish_error = Some(libc::EEXIST);
        assert!(
            super::prepare_staged_session_with(&link, 1, target, &final_name)
                .await
                .is_err()
        );
        let state = link.lock().unwrap();
        assert_eq!(super::link_name(&state.link), Some(ifname("staged0")));
        assert!(super::link_is_up(&state.link));
        assert_eq!(state.set_requests, 1, "a name collision is not retried");
    }

    #[tokio::test]
    async fn hwaddr_change_on_an_up_device_is_deferred_without_touching_it() {
        let link = mock_link(true, 0);
        let original = "02:00:00:00:00:01".parse().unwrap();
        let target = "02:00:00:00:00:02".parse().unwrap();
        assert_eq!(
            super::apply_hwaddr_with(&link, 1, target).await.unwrap(),
            super::HwAddrApply::Deferred
        );
        let state = link.lock().unwrap();
        assert_eq!(state.set_requests, 0, "a running device is never modified");
        assert!(super::link_is_up(&state.link));
        assert_eq!(super::link_hwaddr(&state.link), Some(original));
    }

    #[tokio::test]
    async fn hwaddr_change_on_a_down_device_is_applied_and_verified() {
        let link = mock_link(false, 0);
        let target = "02:00:00:00:00:02".parse().unwrap();
        assert_eq!(
            super::apply_hwaddr_with(&link, 1, target).await.unwrap(),
            super::HwAddrApply::Applied
        );
        {
            let state = link.lock().unwrap();
            assert_eq!(super::link_hwaddr(&state.link), Some(target));
            assert!(!super::link_is_up(&state.link));
            assert_eq!(state.set_requests, 1);
        }
        // The address being in place already is a no-op, even when up.
        link.lock()
            .unwrap()
            .link
            .header
            .flags
            .insert(super::LinkFlags::Up);
        assert_eq!(
            super::apply_hwaddr_with(&link, 1, target).await.unwrap(),
            super::HwAddrApply::Applied
        );
        assert_eq!(link.lock().unwrap().set_requests, 1);
    }

    #[tokio::test]
    async fn hwaddr_change_reports_kernel_failures() {
        let link = mock_link(false, 1);
        let target = "02:00:00:00:00:02".parse().unwrap();
        assert!(super::apply_hwaddr_with(&link, 1, target).await.is_err());
        assert_eq!(
            super::apply_hwaddr_with(&link, 1, target).await.unwrap(),
            super::HwAddrApply::Applied
        );
    }

    #[tokio::test]
    async fn failed_session_rollback_retains_ownership_until_a_successful_retry() {
        struct OwnedSession(Arc<AtomicU32>);
        impl Drop for OwnedSession {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicU32::new(0));
        let mut pending = BTreeMap::from([((10, 20), OwnedSession(dropped.clone()))]);
        let mut attempts = 0;
        // Setup failed after kernel creation. Two unsuccessful rollback
        // attempts must retain the handle and the identifier for retry.
        for _ in 0..2 {
            assert!(super::cleanup_pending_entries(&mut pending, |key| {
                assert_eq!(key, (10, 20));
                attempts += 1;
                std::future::ready(Err(crate::Error::Other("delete failed".into())))
            })
            .await
            .is_err());
            assert!(pending.contains_key(&(10, 20)));
            assert_eq!(dropped.load(Ordering::SeqCst), 0);
        }
        super::cleanup_pending_entries(&mut pending, |key| {
            assert_eq!(key, (10, 20));
            attempts += 1;
            std::future::ready(Ok(()))
        })
        .await
        .unwrap();
        assert_eq!(attempts, 3);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(pending.is_empty());
        super::cleanup_pending_entries(&mut pending, |_| {
            attempts += 1;
            std::future::ready(Ok(()))
        })
        .await
        .unwrap();
        assert_eq!(
            attempts, 3,
            "an acknowledged deletion must not be sent twice"
        );
    }

    fn ifname(name: &str) -> L2tpIfName {
        L2tpIfName::from_name(name).unwrap()
    }

    #[test]
    fn reconnect_verification_rejects_unspecified_local_endpoints() {
        let device = ifname("underlay0");
        for local in [
            IpEndpoint::V4(Ipv4Addr::UNSPECIFIED),
            IpEndpoint::v6(Ipv6Addr::UNSPECIFIED),
            IpEndpoint::v6(Ipv4Addr::UNSPECIFIED.to_ipv6_mapped()),
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

    #[tokio::test]
    async fn vrf_lookup_without_a_controller_or_with_a_missing_interface_returns_none() {
        let loopback = ifname("lo").index().unwrap();
        assert!(!State::interface_is_vrf(loopback).await.unwrap());
        assert!(!State::interface_is_vrf(i32::MAX as u32).await.unwrap());
        assert!(State::interface_is_vrf(u32::MAX).await.is_err());
        assert_eq!(State::interface_vrf_master(loopback).await.unwrap(), None);
        assert_eq!(
            State::interface_vrf_master(i32::MAX as u32).await.unwrap(),
            None
        );
        // Netlink rejects negative signed indexes instead of reporting a
        // missing device. Other lookup errors must not become "no VRF".
        assert!(State::interface_vrf_master(u32::MAX).await.is_err());
    }

    // These tests exercise the real State methods: TunnelHandle cannot be
    // constructed without kernel L2TP support. Run explicitly in a test netns.
    async fn privileged_state(if_name: Option<&str>) -> (State, u32) {
        privileged_state_at(IpAddr::V6(Ipv6Addr::LOCALHOST), if_name).await
    }

    async fn privileged_state_at(remote: IpAddr, if_name: Option<&str>) -> (State, u32) {
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
            panic!("privileged tests require kernel IPv6 L2TP support: {err}");
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
            match state.add_tunnel(id, id + 1, remote, if_name.as_ref()).await {
                Ok(()) => return (state, id),
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

    async fn assert_kernel_endpoints(state: &State, id: u32, local: IpAddr, remote: IpAddr) {
        let info = tunnel_info(state, id).await;
        assert_eq!(info.tunnel_id, l2tp::TunnelId(id));
        assert_eq!(info.peer_tunnel_id, l2tp::TunnelId(id + 1));
        assert_eq!(
            info.encapsulation,
            Encapsulation::Ip {
                local: IpEndpoint::v6(super::to_ipv6_mapped(local)),
                remote: IpEndpoint::v6(super::to_ipv6_mapped(remote)),
            }
        );
        assert!(state.tunnel_is_connected(id).await);
    }

    async fn assert_kernel_tunnel_deleted(state: &State, id: u32) {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let tunnels = state.handle.list_tunnels().await.unwrap();
                if !tunnels.iter().any(|tunnel| tunnel.tunnel_id.0 == id) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("deleted tunnel must disappear from the kernel");
    }

    async fn add_test_dummy(rtnl: &super::Rtnl, name: &str) -> u32 {
        rtnl.handle
            .link()
            .add(rtnetlink::LinkDummy::new(name).up().build())
            .execute()
            .await
            .expect("privileged test requires dummy interfaces");
        ifname(name).index().unwrap()
    }

    async fn add_test_address(
        rtnl: &super::Rtnl,
        index: u32,
        address: IpAddr,
    ) -> rtnetlink::packet_route::address::AddressMessage {
        let prefix = if address.is_ipv4() { 24 } else { 64 };
        let mut request = rtnl.handle.address().add(index, address, prefix);
        // The isolated topology has no duplicate addresses. Avoid a DAD timer
        // making source-selection assertions depend on scheduling.
        request.message_mut().header.flags |=
            rtnetlink::packet_route::address::AddressHeaderFlags::Nodad;
        let message = request.message_mut().clone();
        request.execute().await.expect("add test source address");
        message
    }

    async fn test_address_exists(rtnl: &super::Rtnl, index: u32, address: IpAddr) -> bool {
        let mut addresses = rtnl
            .handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute();
        while let Some(message) = addresses.try_next().await.unwrap() {
            if message.attributes.iter().any(|attr| {
                matches!(attr, rtnetlink::packet_route::address::AddressAttribute::Address(value) if *value == address)
            }) {
                return true;
            }
        }
        false
    }

    async fn exercise_source_reselection(name: &str, addresses: [&str; 4]) {
        let [first, replacement, peer, new_peer] = addresses.map(|s| s.parse::<IpAddr>().unwrap());
        let rtnl = super::Rtnl::connect().unwrap();
        let index = add_test_dummy(&rtnl, name).await;
        let old_address = add_test_address(&rtnl, index, first).await;
        let (state, id) = privileged_state_at(peer, Some(name)).await;
        assert_kernel_endpoints(&state, id, first, peer).await;
        assert_eq!(with_socket(&state, id, socket_bound_interface).await, name);

        // A peer update must change the kernel destination, preserving the
        // chosen source, connection IDs, and device binding.
        state.modify_tunnel(id, new_peer).await.unwrap();
        assert_kernel_endpoints(&state, id, first, new_peer).await;
        assert_eq!(with_socket(&state, id, socket_bound_interface).await, name);

        // Delete before adding a same-prefix replacement: Linux normally
        // deletes secondary IPv4 addresses together with their primary.
        rtnl.handle
            .address()
            .del(old_address)
            .execute()
            .await
            .unwrap();
        assert!(state.reconnect_tunnel(id).await.is_err());
        assert!(!state.tunnel_is_connected(id).await);
        add_test_address(&rtnl, index, replacement).await;
        state.reconnect_tunnel(id).await.unwrap();
        assert_kernel_endpoints(&state, id, replacement, new_peer).await;
        assert_eq!(with_socket(&state, id, socket_bound_interface).await, name);
        assert_eq!(state.bound_interface_index(id).await, Some(index));

        state.delete_tunnel(id).await.unwrap();
        assert_kernel_tunnel_deleted(&state, id).await;
        rtnl.handle.link().del(index).execute().await.unwrap();
        assert_eq!(interface_index(&ifname(name)).await.unwrap(), None);
    }

    #[tokio::test]
    #[ignore = "requires an isolated netns, CAP_NET_ADMIN, dummy and IPv6 L2TP support"]
    async fn privileged_ipv4_peer_update_and_source_reselection() {
        exercise_source_reselection(
            "rsl2tp-v4",
            ["192.0.2.1", "192.0.2.3", "192.0.2.2", "192.0.2.4"],
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires an isolated netns, CAP_NET_ADMIN, dummy and IPv6 L2TP support"]
    async fn privileged_ipv6_peer_update_and_source_reselection() {
        exercise_source_reselection(
            "rsl2tp-v6",
            [
                "2001:db8:155::1",
                "2001:db8:155::3",
                "2001:db8:155::2",
                "2001:db8:155::4",
            ],
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires an isolated netns, CAP_NET_ADMIN, dummy and IPv6 L2TP support"]
    async fn privileged_reconnect_resolves_configured_name_after_rename_and_replacement() {
        let rtnl = super::Rtnl::connect().unwrap();
        let original_name = "rsl2tp-bind";
        let renamed = "rsl2tp-moved";
        let index = add_test_dummy(&rtnl, original_name).await;
        let local = "2001:db8:156::1".parse().unwrap();
        let peer = "2001:db8:156::2".parse().unwrap();
        add_test_address(&rtnl, index, local).await;
        let (state, id) = privileged_state_at(peer, Some(original_name)).await;

        rtnl.set_link(LinkUnspec::new_with_index(index).name(renamed).build())
            .await
            .unwrap();
        // The old device and its route still exist, but its new name was
        // never configured. Reconnect must fail instead of following it or
        // connecting unbound through its route.
        state.forget_tunnel_binding(id).await;
        assert_eq!(state.bound_interface_index(id).await, None);
        assert!(state.reconnect_tunnel(id).await.is_err());
        assert!(!state.tunnel_is_connected(id).await);
        assert_eq!(
            bound_interface(&state, id).await,
            Some(ifname(original_name))
        );
        assert_eq!(
            with_socket(&state, id, socket_bound_interface).await,
            renamed
        );

        let replacement_index = add_test_dummy(&rtnl, original_name).await;
        assert_ne!(index, replacement_index);
        let replacement_local = "2001:db8:156::3".parse().unwrap();
        add_test_address(&rtnl, replacement_index, replacement_local).await;
        // A same-family peer update must also restore a pending binding.
        let peer = "2001:db8:156::5".parse().unwrap();
        state.modify_tunnel(id, peer).await.unwrap();
        assert_kernel_endpoints(&state, id, replacement_local, peer).await;
        // The configured name now selects its replacement and source.
        for _ in 0..2 {
            state.reconnect_tunnel(id).await.unwrap();
            assert_eq!(
                state.bound_interface_index(id).await,
                Some(replacement_index)
            );
            assert_eq!(
                with_socket(&state, id, socket_bound_interface).await,
                original_name
            );
            assert_kernel_endpoints(&state, id, replacement_local, peer).await;
        }

        // Reproduce an incomplete reconnect that stopped after disconnect,
        // before restoring SO_BINDTODEVICE. A same-family update must restore
        // the binding even though its recorded name and index still match.
        {
            let tunnels = state.tunnels.read().await;
            let tunnel = &tunnels[&id];
            tunnel.connected.store(false, Ordering::Release);
            super::tunnel_socket(tunnel).unwrap().disconnect().unwrap();
        }
        let peer = "2001:db8:156::8".parse().unwrap();
        state.modify_tunnel(id, peer).await.unwrap();
        assert!(state.tunnel_is_connected(id).await);
        assert_eq!(
            with_socket(&state, id, socket_bound_interface).await,
            original_name
        );
        assert_kernel_endpoints(&state, id, replacement_local, peer).await;

        rtnl.handle
            .link()
            .del(replacement_index)
            .execute()
            .await
            .unwrap();
        state.forget_tunnel_binding(id).await;
        assert_eq!(state.bound_interface_index(id).await, None);
        assert!(state.reconnect_tunnel(id).await.is_err());
        assert!(!state.tunnel_is_connected(id).await);
        assert_eq!(
            bound_interface(&state, id).await,
            Some(ifname(original_name))
        );

        // A second replacement proves no earlier lookup or index is reused.
        let latest_index = add_test_dummy(&rtnl, original_name).await;
        assert_ne!(latest_index, replacement_index);
        let latest_local = "2001:db8:156::4".parse().unwrap();
        add_test_address(&rtnl, latest_index, latest_local).await;
        state.reconnect_tunnel(id).await.unwrap();
        assert_eq!(state.bound_interface_index(id).await, Some(latest_index));
        assert_eq!(
            with_socket(&state, id, socket_bound_interface).await,
            original_name
        );
        assert_kernel_endpoints(&state, id, latest_local, peer).await;

        // A peer update can race ahead of link notifications. Even with the
        // cached binding still valid, it must select the configured name's
        // replacement rather than follow the old device under its new name.
        rtnl.set_link(
            LinkUnspec::new_with_index(latest_index)
                .name("rsl2tp-moved2")
                .build(),
        )
        .await
        .unwrap();
        let updated_peer = "2001:db8:156::6".parse().unwrap();
        assert!(state.modify_tunnel(id, updated_peer).await.is_err());
        assert_kernel_endpoints(&state, id, latest_local, peer).await;
        let final_index = add_test_dummy(&rtnl, original_name).await;
        let final_local = "2001:db8:156::7".parse().unwrap();
        add_test_address(&rtnl, final_index, final_local).await;
        state.modify_tunnel(id, updated_peer).await.unwrap();
        assert_eq!(state.bound_interface_index(id).await, Some(final_index));
        assert_eq!(
            with_socket(&state, id, socket_bound_interface).await,
            original_name
        );
        assert_kernel_endpoints(&state, id, final_local, updated_peer).await;

        state.delete_tunnel(id).await.unwrap();
        assert_kernel_tunnel_deleted(&state, id).await;
        rtnl.handle.link().del(final_index).execute().await.unwrap();
        rtnl.handle
            .link()
            .del(latest_index)
            .execute()
            .await
            .unwrap();
        rtnl.handle.link().del(index).execute().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated netns, CAP_NET_ADMIN, vrf, dummy, l2tp_eth and IPv6 L2TP support"]
    async fn privileged_vrf_binding_selects_and_refreshes_slave_sources() {
        let rtnl = super::Rtnl::connect().unwrap();
        let vrf_name = "rsl2tp-vrf";
        rtnl.handle
            .link()
            .add(rtnetlink::LinkVrf::new(vrf_name, 4242155).up().build())
            .execute()
            .await
            .expect("privileged test requires VRF support");
        let vrf_index = ifname(vrf_name).index().unwrap();
        let slave_index = add_test_dummy(&rtnl, "rsl2tp-slave").await;
        assert!(State::interface_is_vrf(vrf_index).await.unwrap());
        assert!(!State::interface_is_vrf(slave_index).await.unwrap());
        assert_eq!(
            State::interface_vrf_master(slave_index).await.unwrap(),
            None
        );
        rtnl.set_link(
            LinkUnspec::new_with_index(slave_index)
                .controller(vrf_index)
                .build(),
        )
        .await
        .unwrap();
        assert_eq!(
            State::interface_vrf_master(slave_index).await.unwrap(),
            Some(vrf_index)
        );
        assert_eq!(State::interface_vrf_master(vrf_index).await.unwrap(), None);

        // Connected routes exist only in the VRF table. Successful connect and
        // the exact source therefore exercise VRF routing, not just getsockopt.
        for addresses in [
            ["198.51.100.1", "198.51.100.3", "198.51.100.2"],
            ["2001:db8:157::1", "2001:db8:157::3", "2001:db8:157::2"],
        ] {
            let [first, replacement, peer] = addresses.map(|s| s.parse::<IpAddr>().unwrap());
            let old_address = add_test_address(&rtnl, slave_index, first).await;
            let (state, id) = privileged_state_at(peer, Some(vrf_name)).await;
            assert_kernel_endpoints(&state, id, first, peer).await;
            assert_eq!(state.bound_interface_index(id).await, Some(vrf_index));
            assert_eq!(
                with_socket(&state, id, socket_bound_interface).await,
                vrf_name
            );

            rtnl.handle
                .address()
                .del(old_address)
                .execute()
                .await
                .unwrap();
            assert!(state.reconnect_tunnel(id).await.is_err());
            assert!(!state.tunnel_is_connected(id).await);
            add_test_address(&rtnl, slave_index, replacement).await;
            state.reconnect_tunnel(id).await.unwrap();
            assert_kernel_endpoints(&state, id, replacement, peer).await;
            assert_eq!(state.bound_interface_index(id).await, Some(vrf_index));
            assert_eq!(
                with_socket(&state, id, socket_bound_interface).await,
                vrf_name
            );
            state.delete_tunnel(id).await.unwrap();
            assert_kernel_tunnel_deleted(&state, id).await;
        }

        // Both replacement addresses remain on the slave. A peer update can
        // cross families on the same dual-stack socket without losing its
        // VRF, tunnel, or Ethernet session.
        let local_v4: IpAddr = "198.51.100.3".parse().unwrap();
        let peer_v4: IpAddr = "198.51.100.2".parse().unwrap();
        let local_v6: IpAddr = "2001:db8:157::3".parse().unwrap();
        let peer_v6: IpAddr = "2001:db8:157::2".parse().unwrap();
        let (state, id) = privileged_state_at(peer_v4, Some(vrf_name)).await;
        let session_id = id + 2;
        let session_name = ifname("rsl2tp-family");
        state
            .add_session(
                id,
                session_id,
                session_id,
                &session_name,
                None,
                SessionCookies::default(),
            )
            .await
            .unwrap();
        let session_device = state.session_device(id, session_id).await.unwrap();
        let socket_fd = with_socket(&state, id, AsRawFd::as_raw_fd).await;
        assert_kernel_endpoints(&state, id, local_v4, peer_v4).await;
        assert_eq!(
            state.tunnel_ip_version(id).await,
            Some(crate::config::IpVersion::V4)
        );
        // An invalidated index retains the configured name. If that name
        // exists, a peer update restores its binding without another event.
        state.forget_tunnel_binding(id).await;
        assert_eq!(state.bound_interface_index(id).await, None);
        state.modify_tunnel(id, peer_v6).await.unwrap();
        assert_kernel_endpoints(&state, id, local_v6, peer_v6).await;
        assert_eq!(state.bound_interface_index(id).await, Some(vrf_index));
        state.modify_tunnel(id, peer_v4).await.unwrap();
        assert_kernel_endpoints(&state, id, local_v4, peer_v4).await;

        // When the name is absent, fail before disconnect so a pending bind
        // cannot escape the VRF through the main routing table. Restore the
        // name and let the peer update itself resolve and bind it again.
        let renamed_vrf = "rsl2tp-vrf-old";
        rtnl.set_link(
            LinkUnspec::new_with_index(vrf_index)
                .name(renamed_vrf)
                .build(),
        )
        .await
        .unwrap();
        state.forget_tunnel_binding(id).await;
        let previous = tunnel_info(&state, id).await.encapsulation;
        assert!(state.modify_tunnel(id, peer_v6).await.is_err());
        assert_eq!(tunnel_info(&state, id).await.encapsulation, previous);
        assert!(!state.tunnel_is_connected(id).await);
        assert_eq!(
            with_socket(&state, id, socket_bound_interface).await,
            renamed_vrf
        );
        rtnl.set_link(LinkUnspec::new_with_index(vrf_index).name(vrf_name).build())
            .await
            .unwrap();
        state.modify_tunnel(id, peer_v6).await.unwrap();
        assert_kernel_endpoints(&state, id, local_v6, peer_v6).await;
        assert_eq!(state.bound_interface_index(id).await, Some(vrf_index));
        state.modify_tunnel(id, peer_v4).await.unwrap();
        // A failed cross-family update keeps the previous usable peer and
        // family while the runtime retries the candidate configuration.
        assert!(state
            .modify_tunnel(id, "2001:db8:ffff::2".parse().unwrap())
            .await
            .is_err());
        assert_kernel_endpoints(&state, id, local_v4, peer_v4).await;
        assert!(state.tunnel_is_connected(id).await);
        assert_eq!(
            state.tunnel_ip_version(id).await,
            Some(crate::config::IpVersion::V4)
        );
        for (local, peer, family) in [
            (local_v6, peer_v6, crate::config::IpVersion::V6),
            (local_v4, peer_v4, crate::config::IpVersion::V4),
        ] {
            state.modify_tunnel(id, peer).await.unwrap();
            assert_kernel_endpoints(&state, id, local, peer).await;
            assert_eq!(state.tunnel_ip_version(id).await, Some(family));
            assert_eq!(state.bound_interface_index(id).await, Some(vrf_index));
            assert_eq!(
                with_socket(&state, id, socket_bound_interface).await,
                vrf_name
            );
            assert_eq!(with_socket(&state, id, AsRawFd::as_raw_fd).await, socket_fd);
            assert_eq!(
                state.session_device(id, session_id).await.unwrap(),
                session_device
            );
            assert_eq!(
                interface_index(&session_name).await.unwrap(),
                Some(session_device.0)
            );
            assert_eq!(
                session_info(&state, id, session_id).await.session_id,
                l2tp::SessionId(session_id)
            );
        }
        state.delete_tunnel(id).await.unwrap();
        assert_kernel_tunnel_deleted(&state, id).await;
        assert_interface_deleted(&session_name).await;

        rtnl.handle.link().del(vrf_index).execute().await.unwrap();
        assert_eq!(
            State::interface_vrf_master(slave_index).await.unwrap(),
            None
        );
        rtnl.handle.link().del(slave_index).execute().await.unwrap();
        assert_eq!(
            State::interface_vrf_master(slave_index).await.unwrap(),
            None
        );
    }

    #[tokio::test]
    #[ignore = "requires CAP_NET_ADMIN/root and kernel IPv6 L2TP support"]
    async fn privileged_add_tunnel_records_bound_interface() {
        let (state, id) = privileged_state(Some("lo")).await;
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
        let (state, id) = privileged_state(None).await;
        state.reconnect_tunnel(id).await.unwrap();
        assert!(bound_interface(&state, id).await.is_none());
        assert_eq!(with_socket(&state, id, socket_bound_interface).await, "");
        state.delete_tunnel(id).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires CAP_NET_ADMIN/root and kernel IPv6 L2TP support"]
    async fn privileged_bind_tunnel_interface_records_only_successful_binding() {
        let (state, id) = privileged_state(None).await;
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
        let (state, id) = privileged_state(Some("lo")).await;
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
        let (state, id) = privileged_state(Some("lo")).await;
        assert!(state.tunnel_is_connected(id).await);
        // The isolated test namespace has only loopback, with no route here.
        set_remote(&state, id, "2001:db8::dead".parse().unwrap()).await;
        assert!(state.reconnect_tunnel(id).await.is_err());
        assert!(!state.tunnel_is_connected(id).await);
        assert_eq!(bound_interface(&state, id).await, Some(ifname("lo")));
        assert_eq!(with_socket(&state, id, socket_bound_interface).await, "lo");

        set_remote(&state, id, IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
        state
            .reconnect_tunnel(id)
            .await
            .expect("retry with a reachable route");
        assert!(state.tunnel_is_connected(id).await);
        assert_eq!(with_socket(&state, id, socket_bound_interface).await, "lo");
        assert_eq!(
            tunnel_info(&state, id).await.encapsulation,
            Encapsulation::Ip {
                local: IpEndpoint::v6(Ipv6Addr::LOCALHOST),
                remote: IpEndpoint::v6(Ipv6Addr::LOCALHOST),
            }
        );
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

    async fn assert_interface_deleted(name: &L2tpIfName) {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while interface_index(name).await.unwrap().is_some() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("deleted session interface must disappear from the kernel");
    }

    #[tokio::test]
    #[ignore = "requires CAP_NET_ADMIN/root, l2tp_eth and kernel IPv6 L2TP support"]
    async fn privileged_modify_session_renames_by_index() {
        let (state, id) = privileged_state(None).await;
        let session_id = id + 2;
        let created = ifname("rsl2tp-t0");
        let renamed = ifname("rsl2tp-t1");

        state
            .add_session(
                id,
                session_id,
                session_id,
                &created,
                None,
                SessionCookies::default(),
            )
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
        assert_interface_deleted(&created).await;
        assert_interface_deleted(&renamed).await;
        // Reuse the IDs and name within the same State instance, after the
        // kernel has completed any deferred deletion of the previous device.
        state
            .add_session(
                id,
                session_id,
                session_id,
                &created,
                None,
                SessionCookies::default(),
            )
            .await
            .expect("recreate the deleted session");
        let index = created.index().unwrap();

        // An external deletion can free the index while State still retains
        // its handle. Neither that index nor its session IDs prove ownership.
        state
            .handle
            .delete_session(l2tp::TunnelId(id), l2tp::SessionId(session_id))
            .await
            .unwrap();
        let rtnl = super::Rtnl::connect().unwrap();
        let foreign_name = ifname("rsl2tp-foreign");
        rtnl.handle
            .link()
            .add(
                rtnetlink::LinkDummy::new(foreign_name.to_str().unwrap())
                    .index(index)
                    .build(),
            )
            .execute()
            .await
            .unwrap();
        let foreign_mac = current_hwaddr(index).await;
        assert!(state
            .modify_session(id, session_id, &renamed)
            .await
            .is_err());
        assert!(state
            .set_session_hwaddr(id, session_id, Some(&"02:00:5e:00:53:04".parse().unwrap()))
            .await
            .is_err());
        assert_eq!(foreign_name.index().unwrap(), index);
        assert_eq!(current_hwaddr(index).await, foreign_mac);

        let mut foreign_config = l2tp::SessionConfig::eth(
            l2tp::TunnelId(id),
            l2tp::SessionId(session_id),
            l2tp::SessionId(session_id),
        );
        // Even the creation-time name and IDs can be reused; the registration
        // lifetime must distinguish this foreign replacement.
        foreign_config.ifname = Some(created);
        let mut foreign = state.handle.create_session(foreign_config).await.unwrap();
        foreign.set_auto_delete(false);
        state.delete_session(id, session_id).await.unwrap();
        assert!(!state.has_session(id, session_id).await);
        foreign
            .get()
            .await
            .expect("foreign session must survive stale-handle cleanup");
        assert_eq!(foreign_name.index().unwrap(), index);

        // Intentional removal of our parent tunnel closes its owned socket
        // and removes every session still attached to that tunnel.
        state.delete_tunnel(id).await.unwrap();
        assert!(!state.has_tunnel(id).await);
        assert_interface_deleted(&created).await;
        assert_kernel_tunnel_deleted(&state, id).await;
        assert_eq!(foreign_name.index().unwrap(), index);
        rtnl.handle.link().del(index).execute().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires CAP_NET_ADMIN/root, l2tp_eth and kernel IPv6 L2TP support"]
    async fn privileged_session_hwaddr_is_applied_changed_and_restored() {
        let (state, id) = privileged_state(None).await;
        let session_id = id + 2;
        let name = ifname("rsl2tp-t2");
        let first: HwAddr = "02:00:5e:00:53:01".parse().unwrap();
        let second: HwAddr = "02:00:5e:00:53:02".parse().unwrap();

        use super::HwAddrApply;

        assert_eq!(
            state
                .add_session(
                    id,
                    session_id,
                    session_id,
                    &name,
                    Some(&first),
                    SessionCookies::default(),
                )
                .await
                .expect("create session with hardware address"),
            HwAddrApply::Applied
        );
        let (index, initial) = session_device(&state, id, session_id).await;
        let initial = initial.expect("l2tpeth devices get a random address");
        assert_ne!(initial, first);
        assert_eq!(current_hwaddr(index).await, Some(first));
        assert_eq!(interface_index(&name).await.unwrap(), Some(index));
        let staging = session_info(&state, id, session_id).await.ifname.unwrap();
        assert_ne!(staging, name);
        assert!(staging.to_str().unwrap().starts_with("rsl2tp-t"));
        assert_eq!(interface_index(&staging).await.unwrap(), None);
        assert!(!state.session_hwaddr_pending(id, session_id).await);

        // A running device is left alone: the change is deferred.
        let rtnl = super::Rtnl::connect().unwrap();
        rtnl.set_link(LinkUnspec::new_with_index(index).up().build())
            .await
            .expect("bring the device up");
        assert_eq!(
            state
                .set_session_hwaddr(id, session_id, Some(&second))
                .await
                .unwrap(),
            HwAddrApply::Deferred
        );
        assert_eq!(current_hwaddr(index).await, Some(first));
        assert!(super::link_is_up(&rtnl.get_link(index).await.unwrap()));
        assert!(state.session_hwaddr_pending(id, session_id).await);

        // Once the device is down, the deferred change applies.
        rtnl.set_link(LinkUnspec::new_with_index(index).down().build())
            .await
            .expect("take the device down");
        assert_eq!(
            state
                .set_session_hwaddr(id, session_id, Some(&second))
                .await
                .unwrap(),
            HwAddrApply::Applied
        );
        assert_eq!(current_hwaddr(index).await, Some(second));
        assert!(!state.session_hwaddr_pending(id, session_id).await);

        // Setting the current address again is a no-op, up or down.
        rtnl.set_link(LinkUnspec::new_with_index(index).up().build())
            .await
            .unwrap();
        assert_eq!(
            state
                .set_session_hwaddr(id, session_id, Some(&second))
                .await
                .unwrap(),
            HwAddrApply::Applied
        );

        // Dropping the configured address restores the kernel's choice,
        // again only while the device is down.
        assert_eq!(
            state
                .set_session_hwaddr(id, session_id, None)
                .await
                .unwrap(),
            HwAddrApply::Deferred
        );
        rtnl.set_link(LinkUnspec::new_with_index(index).down().build())
            .await
            .unwrap();
        assert_eq!(
            state
                .set_session_hwaddr(id, session_id, None)
                .await
                .expect("restore the initial address"),
            HwAddrApply::Applied
        );
        assert_eq!(current_hwaddr(index).await, Some(initial));

        state.delete_session(id, session_id).await.unwrap();
        assert_interface_deleted(&name).await;
        state.delete_tunnel(id).await.unwrap();
        assert_kernel_tunnel_deleted(&state, id).await;
    }

    #[tokio::test]
    #[ignore = "requires an isolated netns, CAP_NET_ADMIN, dummy, l2tp_eth and IPv6 L2TP support"]
    async fn privileged_staged_session_retains_children_across_publication_failures() {
        let (state, id) = privileged_state(None).await;
        let rtnl = super::Rtnl::connect().unwrap();
        let session_id = id + 2;
        let final_name = ifname("rsl2tp-publish");
        let target: HwAddr = "02:00:5e:00:53:03".parse().unwrap();

        // Reserve the next staging candidate. The ignored kernel suite runs
        // sequentially; allocation must skip this foreign interface on EEXIST.
        let previous = super::next_session_staging_name().unwrap();
        let number = usize::from_str_radix(
            previous.to_str().unwrap().strip_prefix("rsl2tp-t").unwrap(),
            16,
        )
        .unwrap();
        let occupied = ifname(&format!("rsl2tp-t{:06x}", (number + 1) & 0x00ff_ffff));
        let foreign_staging = add_test_dummy(&rtnl, occupied.to_str().unwrap()).await;
        let foreign_final = add_test_dummy(&rtnl, final_name.to_str().unwrap()).await;
        let before = current_hwaddr(foreign_final).await;
        assert!(state
            .add_session(
                id,
                session_id,
                session_id,
                &final_name,
                Some(&target),
                SessionCookies::default()
            )
            .await
            .is_err());
        assert!(!state.has_session(id, session_id).await);
        let staged_index = state.pending_sessions.read().await[&(id, session_id)]
            .handle
            .ifindex()
            .unwrap();
        assert_eq!(occupied.index().unwrap(), foreign_staging);
        assert_eq!(final_name.index().unwrap(), foreign_final);
        assert_eq!(current_hwaddr(foreign_final).await, before);
        let child_name = ifname("rsl2tp-child");
        rtnl.handle
            .link()
            .add(rtnetlink::LinkVlan::new(child_name.to_str().unwrap(), staged_index, 37).build())
            .execute()
            .await
            .unwrap();
        let child_index = child_name.index().unwrap();
        for index in [staged_index, child_index] {
            rtnl.set_link(LinkUnspec::new_with_index(index).up().build())
                .await
                .unwrap();
        }
        let child_address = "2001:db8:37::1".parse().unwrap();
        add_test_address(&rtnl, child_index, child_address).await;
        state
            .retain_pending_sessions(&std::collections::BTreeSet::from([(id, session_id)]))
            .await
            .unwrap();
        assert!(state
            .add_session(
                id,
                session_id,
                session_id,
                &final_name,
                Some(&target),
                SessionCookies::default()
            )
            .await
            .is_err());
        assert_eq!(child_name.index().unwrap(), child_index);
        assert!(test_address_exists(&rtnl, child_index, child_address).await);

        // The same device can be published after the final-name collision ends.
        rtnl.handle
            .link()
            .del(foreign_final)
            .execute()
            .await
            .unwrap();
        assert_eq!(
            state
                .add_session(
                    id,
                    session_id,
                    session_id,
                    &final_name,
                    Some(&target),
                    SessionCookies::default()
                )
                .await
                .unwrap(),
            super::HwAddrApply::Applied
        );
        let (index, _) = session_device(&state, id, session_id).await;
        assert_eq!(index, staged_index);
        assert_eq!(final_name.index().unwrap(), index);
        assert_eq!(current_hwaddr(index).await, Some(target));
        assert_eq!(child_name.index().unwrap(), child_index);
        assert!(test_address_exists(&rtnl, child_index, child_address).await);
        let staging = session_info(&state, id, session_id).await.ifname.unwrap();
        assert_eq!(interface_index(&staging).await.unwrap(), None);
        state.delete_session(id, session_id).await.unwrap();
        assert_interface_deleted(&final_name).await;
        assert_interface_deleted(&child_name).await;

        // Withdrawing an incomplete session still removes its owned device,
        // while keeping the unrelated final-name occupant and parent tunnel.
        let foreign_final = add_test_dummy(&rtnl, final_name.to_str().unwrap()).await;
        assert!(state
            .add_session(
                id,
                session_id,
                session_id,
                &final_name,
                Some(&target),
                SessionCookies::default()
            )
            .await
            .is_err());
        let unpublished = *state.pending_sessions.read().await[&(id, session_id)]
            .handle
            .ifname()
            .unwrap();
        state
            .retain_pending_sessions(&BTreeSet::new())
            .await
            .unwrap();
        assert!(state.pending_sessions.read().await.is_empty());
        assert_interface_deleted(&unpublished).await;
        assert_eq!(final_name.index().unwrap(), foreign_final);
        assert!(state.has_tunnel(id).await);
        rtnl.handle
            .link()
            .del(foreign_final)
            .execute()
            .await
            .unwrap();
        state.delete_tunnel(id).await.unwrap();
        assert_kernel_tunnel_deleted(&state, id).await;
        assert_eq!(occupied.index().unwrap(), foreign_staging);
        rtnl.handle
            .link()
            .del(foreign_staging)
            .execute()
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires CAP_NET_ADMIN/root, l2tp_eth and kernel IPv6 L2TP support"]
    async fn privileged_session_cookies_are_applied() {
        let (state, id) = privileged_state(None).await;
        let session_id = id + 2;
        let name = ifname("rsl2tp-t3");
        let cookie: Cookie = "deadbeef".parse().unwrap();
        let peer_cookie: Cookie = "0011223344556677".parse().unwrap();

        state
            .add_session(
                id,
                session_id,
                session_id,
                &name,
                None,
                SessionCookies {
                    cookie: Some(cookie),
                    peer_cookie: Some(peer_cookie),
                },
            )
            .await
            .expect("create session with cookies");
        let info = session_info(&state, id, session_id).await;
        assert_eq!(info.cookie.as_bytes(), cookie.as_bytes());
        assert_eq!(info.peer_cookie.as_bytes(), peer_cookie.as_bytes());
        state.delete_session(id, session_id).await.unwrap();
        assert_interface_deleted(&name).await;

        // Without cookies the kernel reports none: the 0.1.x wire format.
        state
            .add_session(
                id,
                session_id,
                session_id,
                &name,
                None,
                SessionCookies::default(),
            )
            .await
            .expect("create session without cookies");
        let info = session_info(&state, id, session_id).await;
        assert!(info.cookie.is_empty());
        assert!(info.peer_cookie.is_empty());

        state.delete_tunnel(id).await.unwrap();
        assert_interface_deleted(&name).await;
        assert_kernel_tunnel_deleted(&state, id).await;
    }

    #[tokio::test]
    #[ignore = "requires an isolated netns, CAP_NET_ADMIN, dummy, vrf and IPv6 L2TP support"]
    async fn privileged_discard_route_falls_back_to_the_null_device() {
        use super::NULL_DEVICE;
        use crate::config::TunnelConfig;
        use rtnetlink::packet_route::route::RouteType;
        use rtnetlink::RouteMessageBuilder;

        let null = ifname(NULL_DEVICE);
        let discard = IpAddr::V6(TunnelConfig::NO_PEER_ADDR);
        let state = State::new().await.expect("create L2TP handle");
        let id = 1_600_000_000 + (std::process::id() % 100_000) * 8;
        assert_eq!(interface_index(&null).await.unwrap(), None);

        // The isolated namespace routes nothing: without help, a tunnel to
        // the discard address cannot be created.
        let err = state
            .add_tunnel(id, id + 1, discard, None)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, crate::Error::L2tp(l2tp::Error::Io(e)) if e.raw_os_error() == Some(libc::ENETUNREACH)),
            "{err}"
        );
        assert!(!State::discard_route_exists(None).await.unwrap());
        state.route_discard_to_null_device(None).await.unwrap();
        let index = interface_index(&null).await.unwrap().expect("null device");
        let rtnl = super::Rtnl::connect().unwrap();
        let link = rtnl.get_link(index).await.unwrap();
        assert!(super::link_is_dummy(&link));
        assert!(super::link_is_up(&link));
        // Now the host routes it; routing it again is harmless.
        assert!(State::discard_route_exists(None).await.unwrap());
        state.route_discard_to_null_device(None).await.unwrap();
        state
            .add_tunnel(id, id + 1, discard, None)
            .await
            .expect("tunnel to the discard address through the null device");
        let Encapsulation::Ip { local, remote } = tunnel_info(&state, id).await.encapsulation
        else {
            panic!("expected IP encapsulation");
        };
        assert_eq!(remote, IpEndpoint::v6(TunnelConfig::NO_PEER_ADDR));
        // Without a global address the kernel selects a link-local source,
        // the null device's own: enough to connect, as on an IPv4-only host.
        assert!(
            matches!(local.ip(), IpAddr::V6(addr) if addr.is_unicast_link_local()),
            "{local}"
        );

        // A newly resolved IPv6 peer must select the real underlay's global
        // source, keeping the socket and Ethernet session created offline.
        let session_id = id + 4;
        let session_name = ifname("rsl2tp-nulls");
        state
            .add_session(
                id,
                session_id,
                session_id,
                &session_name,
                None,
                SessionCookies::default(),
            )
            .await
            .unwrap();
        let session_before = session_device(&state, id, session_id).await;
        let fd = with_socket(&state, id, AsRawFd::as_raw_fd).await;
        let real_index = add_test_dummy(&rtnl, "rsl2tp-nreal").await;
        let real_source: IpAddr = "2001:db8:158::1".parse().unwrap();
        let real_peer: IpAddr = "2001:db8:158::2".parse().unwrap();
        add_test_address(&rtnl, real_index, real_source).await;
        state.modify_tunnel(id, real_peer).await.unwrap();
        assert_kernel_endpoints(&state, id, real_source, real_peer).await;
        assert_eq!(with_socket(&state, id, AsRawFd::as_raw_fd).await, fd);
        assert_eq!(session_device(&state, id, session_id).await, session_before);
        assert_eq!(with_socket(&state, id, socket_bound_interface).await, "");

        // A VRF with an unreachable default route, the usual VRF setup,
        // needs the route in its own table.
        let vrf_name = "rsl2tp-nullvrf";
        let table = 4242156;
        rtnl.handle
            .link()
            .add(rtnetlink::LinkVrf::new(vrf_name, table).up().build())
            .execute()
            .await
            .expect("privileged test requires VRF support");
        let vrf_index = ifname(vrf_name).index().unwrap();
        // A VRF has members; their link-local addresses are the only
        // source candidates for a socket bound to it, as on an IPv4-only
        // VRF.
        let slave_index = add_test_dummy(&rtnl, "rsl2tp-nslave").await;
        rtnl.set_link(
            LinkUnspec::new_with_index(slave_index)
                .controller(vrf_index)
                .build(),
        )
        .await
        .unwrap();
        rtnl.handle
            .route()
            .add(
                RouteMessageBuilder::<Ipv6Addr>::new()
                    .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
                    .kind(RouteType::Unreachable)
                    .table_id(table)
                    .build(),
            )
            .execute()
            .await
            .expect("unreachable default route in the VRF table");
        assert!(state
            .add_tunnel(id + 2, id + 3, discard, Some(&ifname(vrf_name)))
            .await
            .is_err());
        assert!(!State::discard_route_exists(Some(vrf_index)).await.unwrap());
        state
            .route_discard_to_null_device(Some(vrf_index))
            .await
            .unwrap();
        assert!(State::discard_route_exists(Some(vrf_index)).await.unwrap());
        state
            .add_tunnel(id + 2, id + 3, discard, Some(&ifname(vrf_name)))
            .await
            .expect("tunnel in the VRF through the null device");

        state.delete_tunnel(id).await.unwrap();
        state.delete_tunnel(id + 2).await.unwrap();
        assert_interface_deleted(&session_name).await;
        state.remove_null_device().await.unwrap();
        assert_eq!(interface_index(&null).await.unwrap(), None);
        // Removing it again is fine.
        state.remove_null_device().await.unwrap();
        rtnl.handle.link().del(slave_index).execute().await.unwrap();
        rtnl.handle.link().del(vrf_index).execute().await.unwrap();
        rtnl.handle.link().del(real_index).execute().await.unwrap();
        assert_kernel_tunnel_deleted(&state, id).await;
    }

    #[tokio::test]
    #[ignore = "requires an isolated netns, CAP_NET_ADMIN, dummy, l2tp_eth and IPv6 L2TP support"]
    async fn privileged_discard_peer_update_replaces_removed_source() {
        let rtnl = super::Rtnl::connect().unwrap();
        let name = "rsl2tp-dsrc";
        let index = add_test_dummy(&rtnl, name).await;
        let first: IpAddr = "2001:db8:159::1".parse().unwrap();
        let replacement: IpAddr = "2001:db8:159::3".parse().unwrap();
        let peer: IpAddr = "2001:db8:159::2".parse().unwrap();
        let discard = IpAddr::V6(crate::config::TunnelConfig::NO_PEER_ADDR);
        let old_address = add_test_address(&rtnl, index, first).await;
        rtnl.route_to_device(
            crate::config::TunnelConfig::NO_PEER_ADDR,
            index,
            super::RT_TABLE_MAIN,
        )
        .await
        .unwrap();
        let (state, id) = privileged_state_at(discard, Some(name)).await;
        let session_id = id + 2;
        let session_name = ifname("rsl2tp-dsrcs");
        state
            .add_session(
                id,
                session_id,
                session_id,
                &session_name,
                None,
                SessionCookies::default(),
            )
            .await
            .unwrap();
        let session_before = session_device(&state, id, session_id).await;
        let fd = with_socket(&state, id, AsRawFd::as_raw_fd).await;
        assert_kernel_endpoints(&state, id, first, discard).await;

        // Offline address notifications deliberately do not reconnect the
        // placeholder. Updating its peer must discard this stale source.
        rtnl.handle
            .address()
            .del(old_address)
            .execute()
            .await
            .unwrap();
        add_test_address(&rtnl, index, replacement).await;
        state.modify_tunnel(id, peer).await.unwrap();
        assert_kernel_endpoints(&state, id, replacement, peer).await;
        assert_eq!(with_socket(&state, id, socket_bound_interface).await, name);
        assert_eq!(state.bound_interface_index(id).await, Some(index));
        assert_eq!(with_socket(&state, id, AsRawFd::as_raw_fd).await, fd);
        assert_eq!(session_device(&state, id, session_id).await, session_before);

        state.delete_tunnel(id).await.unwrap();
        assert_interface_deleted(&session_name).await;
        assert_kernel_tunnel_deleted(&state, id).await;
        rtnl.handle.link().del(index).execute().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated netns, CAP_NET_ADMIN and dummy support"]
    async fn privileged_null_device_cleanup_preserves_foreign_devices() {
        let rtnl = super::Rtnl::connect().unwrap();
        let state = State::new().await.unwrap();
        let foreign = add_test_dummy(&rtnl, super::NULL_DEVICE).await;
        let address: IpAddr = "2001:db8:160::1".parse().unwrap();
        // The administrative device stays down, with its address.
        rtnl.set_link(LinkUnspec::new_with_index(foreign).down().build())
            .await
            .unwrap();
        add_test_address(&rtnl, foreign, address).await;
        let before = rtnl.get_link(foreign).await.unwrap();
        state.route_discard_to_null_device(None).await.unwrap();
        let owned = ifname("rsl2tpnull1").index().unwrap();
        assert_ne!(owned, foreign);
        assert_eq!(
            super::link_is_up(&rtnl.get_link(foreign).await.unwrap()),
            super::link_is_up(&before)
        );
        state.route_discard_to_null_device(None).await.unwrap();
        assert_eq!(ifname("rsl2tpnull1").index().unwrap(), owned);

        // Renaming the owned device does not transfer ownership to a new
        // device given its old name. Reuse and cleanup still follow its index.
        super::rename_interface(owned, &ifname("rsl2tp-nowned"))
            .await
            .unwrap();
        let replacement = add_test_dummy(&rtnl, "rsl2tpnull1").await;
        state.route_discard_to_null_device(None).await.unwrap();
        assert_eq!(state.discard_resources.lock().await.devices.len(), 1);
        state.remove_null_device().await.unwrap();
        assert!(rtnl.find_link(owned).await.unwrap().is_none());
        assert_eq!(ifname("rsl2tpnull1").index().unwrap(), replacement);
        assert_eq!(ifname(super::NULL_DEVICE).index().unwrap(), foreign);
        let mut addresses = rtnl
            .handle
            .address()
            .get()
            .set_link_index_filter(foreign)
            .execute();
        let mut found = false;
        while let Some(message) = addresses.try_next().await.unwrap() {
            found |= message.attributes.iter().any(|attr| {
                matches!(attr, rtnetlink::packet_route::address::AddressAttribute::Address(value) if *value == address)
            });
        }
        assert!(found, "foreign address must survive cleanup");

        // A deleted owned link can be replaced before shutdown. The new link
        // must survive too; reusing the index does not match the creation MAC.
        state.route_discard_to_null_device(None).await.unwrap();
        let gone = ifname("rsl2tpnull2").index().unwrap();
        rtnl.handle.link().del(gone).execute().await.unwrap();
        rtnl.handle
            .link()
            .add(
                rtnetlink::LinkDummy::new("rsl2tpnull2")
                    .index(gone)
                    .up()
                    .build(),
            )
            .execute()
            .await
            .unwrap();
        let replacement2 = ifname("rsl2tpnull2").index().unwrap();
        assert_eq!(replacement2, gone, "exercise actual interface-index reuse");
        state.remove_null_device().await.unwrap();
        assert_eq!(ifname("rsl2tpnull2").index().unwrap(), replacement2);

        // Ownership starts at creation, independently of route installation.
        let uninstalled = {
            let mut resources = state.discard_resources.lock().await;
            State::null_device(&rtnl, &mut resources.devices)
                .await
                .unwrap()
        };
        assert!(rtnl
            .route_to_device(
                crate::config::TunnelConfig::NO_PEER_ADDR,
                u32::MAX,
                super::RT_TABLE_MAIN
            )
            .await
            .is_err());
        state.remove_null_device().await.unwrap();
        assert!(rtnl.find_link(uninstalled).await.unwrap().is_none());
        state.remove_null_device().await.unwrap();
        for index in [foreign, replacement, replacement2] {
            rtnl.handle.link().del(index).execute().await.unwrap();
        }
    }

    async fn discard_routes_in_table(rtnl: &super::Rtnl, table: u32) -> Vec<super::RouteMessage> {
        use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute};

        let mut dump = rtnl
            .handle
            .route()
            .get(rtnetlink::RouteMessageBuilder::<Ipv6Addr>::new().build())
            .execute();
        let mut routes = Vec::new();
        while let Some(route) = dump.try_next().await.unwrap() {
            let current_table = route
                .attributes
                .iter()
                .find_map(|attr| match attr {
                    RouteAttribute::Table(table) => Some(*table),
                    _ => None,
                })
                .unwrap_or(u32::from(route.header.table));
            if current_table == table
                && route.header.destination_prefix_length == 128
                && route.attributes.iter().any(|attr| {
                    matches!(attr, RouteAttribute::Destination(RouteAddress::Inet6(address))
                        if *address == crate::config::TunnelConfig::NO_PEER_ADDR)
                })
            {
                routes.push(route);
            }
        }
        routes
    }

    async fn remove_discard_routes(rtnl: &super::Rtnl, table: u32) {
        for route in discard_routes_in_table(rtnl, table).await {
            rtnl.handle.route().del(route).execute().await.unwrap();
        }
    }

    async fn assert_discard_route_device(rtnl: &super::Rtnl, table: u32, index: u32) {
        let routes = discard_routes_in_table(rtnl, table).await;
        assert_eq!(
            routes.len(),
            1,
            "exactly one discard route in table {table}"
        );
        assert!(
            routes[0].attributes.iter().any(|attr| {
                matches!(attr, super::RouteAttribute::Oif(current) if *current == index)
            }),
            "discard route in table {table} must use interface index {index}"
        );
    }

    #[tokio::test]
    #[ignore = "requires an isolated netns, CAP_NET_ADMIN and dummy support"]
    async fn privileged_discard_route_repair_preserves_foreign_routes_and_stops_after_cleanup() {
        let rtnl = super::Rtnl::connect().unwrap();
        let state = State::new().await.unwrap();
        let null_name = ifname(super::NULL_DEVICE);
        let table = super::RT_TABLE_MAIN;
        let discard = crate::config::TunnelConfig::NO_PEER_ADDR;
        // A route event before fallback was needed must create nothing.
        state.restore_discard_routes().await.unwrap();
        assert_eq!(interface_index(&null_name).await.unwrap(), None);

        state.route_discard_to_null_device(None).await.unwrap();
        let original = null_name.index().unwrap();
        remove_discard_routes(&rtnl, table).await;
        assert!(discard_routes_in_table(&rtnl, table).await.is_empty());
        state.restore_discard_routes().await.unwrap();
        assert_discard_route_device(&rtnl, table, original).await;

        // Another manager's replacement for the same prefix/metric wins.
        // A separate real-peer route must also remain untouched.
        let foreign = add_test_dummy(&rtnl, "rsl2tp-rforeign").await;
        let unrelated: Ipv6Addr = "2001:db8:161::99".parse().unwrap();
        remove_discard_routes(&rtnl, table).await;
        rtnl.route_to_device(discard, foreign, table).await.unwrap();
        rtnl.route_to_device(unrelated, foreign, table)
            .await
            .unwrap();
        state.restore_discard_routes().await.unwrap();
        assert_discard_route_device(&rtnl, table, foreign).await;
        state.route_discard_to_null_device(None).await.unwrap();
        assert_discard_route_device(&rtnl, table, foreign).await;
        assert!(rtnl.routes(unrelated, None).await.unwrap());

        // Both initial installation and repair respect a reject route.
        remove_discard_routes(&rtnl, table).await;
        rtnl.handle
            .route()
            .add(
                rtnetlink::RouteMessageBuilder::<Ipv6Addr>::new()
                    .destination_prefix(discard, 128)
                    .table_id(table)
                    .kind(rtnetlink::packet_route::route::RouteType::Unreachable)
                    .build(),
            )
            .execute()
            .await
            .unwrap();
        state.restore_discard_routes().await.unwrap();
        state.route_discard_to_null_device(None).await.unwrap();
        let preserved = discard_routes_in_table(&rtnl, table).await;
        assert_eq!(preserved.len(), 1);
        assert_eq!(
            preserved[0].header.kind,
            rtnetlink::packet_route::route::RouteType::Unreachable
        );

        // If the owned link disappeared too, allocate a fresh owned device.
        remove_discard_routes(&rtnl, table).await;
        rtnl.handle.link().del(original).execute().await.unwrap();
        state.restore_discard_routes().await.unwrap();
        let replacement = null_name.index().unwrap();
        assert_ne!(replacement, original);
        assert_discard_route_device(&rtnl, table, replacement).await;

        state.remove_null_device().await.unwrap();
        state.restore_discard_routes().await.unwrap();
        assert_eq!(interface_index(&null_name).await.unwrap(), None);
        assert!(discard_routes_in_table(&rtnl, table).await.is_empty());
        assert!(rtnl.routes(unrelated, None).await.unwrap());
        rtnl.handle.link().del(foreign).execute().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated netns, CAP_NET_ADMIN, dummy and VRF support"]
    async fn privileged_discard_route_repair_resolves_replacement_vrf_names_and_tables() {
        let rtnl = super::Rtnl::connect().unwrap();
        let state = State::new().await.unwrap();
        let name = ifname("rsl2tp-rvrf");
        let old_table = 4_242_160;
        let new_table = old_table + 1;
        rtnl.handle
            .link()
            .add(
                rtnetlink::LinkVrf::new(name.to_str().unwrap(), old_table)
                    .up()
                    .build(),
            )
            .execute()
            .await
            .unwrap();
        let original = name.index().unwrap();
        // Record the VRF first, so a failed repair there cannot prevent the
        // later main-table repair from running.
        state
            .route_discard_to_null_device(Some(original))
            .await
            .unwrap();
        state.route_discard_to_null_device(None).await.unwrap();
        let null_index = ifname(super::NULL_DEVICE).index().unwrap();
        rtnl.handle.link().del(original).execute().await.unwrap();
        remove_discard_routes(&rtnl, old_table).await;
        remove_discard_routes(&rtnl, super::RT_TABLE_MAIN).await;
        assert!(state.restore_discard_routes().await.is_err());
        assert_discard_route_device(&rtnl, super::RT_TABLE_MAIN, null_index).await;
        assert!(discard_routes_in_table(&rtnl, old_table).await.is_empty());

        // The same name occupied by a non-VRF must remain an error, never
        // quietly selecting the main table or forgetting the pending VRF.
        let wrong_kind = add_test_dummy(&rtnl, name.to_str().unwrap()).await;
        remove_discard_routes(&rtnl, super::RT_TABLE_MAIN).await;
        assert!(state.restore_discard_routes().await.is_err());
        assert_discard_route_device(&rtnl, super::RT_TABLE_MAIN, null_index).await;
        assert!(discard_routes_in_table(&rtnl, old_table).await.is_empty());
        rtnl.handle.link().del(wrong_kind).execute().await.unwrap();

        rtnl.handle
            .link()
            .add(
                rtnetlink::LinkVrf::new(name.to_str().unwrap(), new_table)
                    .up()
                    .build(),
            )
            .execute()
            .await
            .unwrap();
        let replacement = name.index().unwrap();
        assert_ne!(replacement, original);
        state.restore_discard_routes().await.unwrap();
        assert_discard_route_device(&rtnl, new_table, null_index).await;
        assert!(discard_routes_in_table(&rtnl, old_table).await.is_empty());

        state.remove_null_device().await.unwrap();
        state.restore_discard_routes().await.unwrap();
        assert!(discard_routes_in_table(&rtnl, new_table).await.is_empty());
        assert!(discard_routes_in_table(&rtnl, super::RT_TABLE_MAIN)
            .await
            .is_empty());
        assert_eq!(
            interface_index(&ifname(super::NULL_DEVICE)).await.unwrap(),
            None
        );
        rtnl.handle.link().del(replacement).execute().await.unwrap();
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
