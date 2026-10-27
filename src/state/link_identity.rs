//! Tracks netdevice lifetimes separately from their reusable names and indices.
//!
//! The subscription starts before session creation. Before a mutation, a
//! GETLINK response on that same socket and a drain of earlier notifications
//! detect deletion, namespace moves, and index reuse. Linux does not provide an
//! atomic lifetime-token-plus-SETLINK operation: callers must still keep the
//! interval between validation and mutation short.
//!
//! A lifetime ends in one of two ways, which callers treat differently: the
//! kernel announced the device's removal ([`Invalidation::Deleted`]), or the
//! subscription lost notifications and can no longer tell
//! ([`Invalidation::Lost`]). After a loss, the subscription is reopened and
//! reseeded, so devices created afterwards get fresh identities, but the
//! identities captured before cannot be proved again.

use crate::error::{Error, Result};
use futures_util::{stream::BoxStream, FutureExt, StreamExt, TryStreamExt};
use l2tp::L2tpIfName;
use rtnetlink::packet_core::{NetlinkMessage, NetlinkPayload};
use rtnetlink::packet_route::{
    link::{LinkAttribute, LinkMessage},
    AddressFamily, RouteNetlinkMessage,
};
use rtnetlink::{sys::SocketAddr, MulticastGroup};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc, Mutex, Weak,
    },
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

const LIVE: u8 = 0;
const DELETED: u8 = 1;
const LOST: u8 = 2;

/// Why a device's lifetime can no longer be proved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Invalidation {
    /// The kernel announced the device's removal from this namespace: it
    /// was deleted, or moved to another namespace.
    Deleted,
    /// Link notifications were lost, so the device may or may not still be
    /// the one captured.
    Lost,
}

impl fmt::Display for Invalidation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Invalidation::Deleted => "its device was removed from this namespace",
            Invalidation::Lost => "link notifications were lost",
        })
    }
}

#[derive(Clone)]
pub(super) struct LinkIdentity {
    index: u32,
    state: Arc<AtomicU8>,
}

impl LinkIdentity {
    fn new(index: u32) -> Self {
        Self {
            index,
            state: Arc::new(AtomicU8::new(LIVE)),
        }
    }

    pub(super) fn index(&self) -> u32 {
        self.index
    }

    fn invalidation(&self) -> Option<Invalidation> {
        match self.state.load(Ordering::Acquire) {
            DELETED => Some(Invalidation::Deleted),
            LOST => Some(Invalidation::Lost),
            _ => None,
        }
    }

    fn is_live(&self) -> bool {
        self.invalidation().is_none()
    }

    /// The first invalidation wins: a loss cannot upgrade an observed
    /// deletion, nor the other way round.
    fn invalidate(&self, why: Invalidation) {
        let state = match why {
            Invalidation::Deleted => DELETED,
            Invalidation::Lost => LOST,
        };
        let _ = self
            .state
            .compare_exchange(LIVE, state, Ordering::AcqRel, Ordering::Relaxed);
    }
}

struct Capture {
    /// The name the device is created under.
    name: String,
    first: Option<LinkIdentity>,
    lost: bool,
}

pub(super) struct CreationWatch {
    capture: Arc<Mutex<Capture>>,
}

pub(super) enum LinkStatus {
    Live(LinkMessage),
    Invalidated(Invalidation),
}

struct PendingWatch {
    capture: Weak<Mutex<Capture>>,
}

#[derive(Default)]
struct Ledger {
    links: BTreeMap<u32, LinkIdentity>,
    watches: Vec<PendingWatch>,
}

impl Ledger {
    fn seed(&mut self, links: impl IntoIterator<Item = LinkMessage>) {
        for link in links {
            self.links
                .entry(link.header.index)
                .or_insert_with(|| LinkIdentity::new(link.header.index));
        }
    }

    fn arm(&mut self, name: String) -> CreationWatch {
        self.watches
            .retain(|watch| watch.capture.strong_count() != 0);
        let capture = Arc::new(Mutex::new(Capture {
            name,
            first: None,
            lost: false,
        }));
        self.watches.push(PendingWatch {
            capture: Arc::downgrade(&capture),
        });
        CreationWatch { capture }
    }

    fn new_link(&mut self, link: LinkMessage) {
        // AF_BRIDGE/AF_INET6 notifications describe protocol-specific state;
        // their NEWLINK/DELLINK pairs do not delimit netdevice lifetimes.
        if link.header.interface_family != AddressFamily::Unspec {
            return;
        }
        if self.links.contains_key(&link.header.index) {
            return;
        }
        let identity = LinkIdentity::new(link.header.index);
        let name = link_name(&link);
        self.watches.retain(|watch| {
            let Some(capture) = watch.capture.upgrade() else {
                return false;
            };
            let mut capture = capture.lock().expect("creation watch poisoned");
            if !capture.lost && capture.first.is_none() && name == Some(capture.name.as_str()) {
                capture.first = Some(identity.clone());
            }
            true
        });
        self.links.insert(identity.index, identity);
    }

    fn delete_link(&mut self, link: LinkMessage) {
        if link.header.interface_family != AddressFamily::Unspec {
            return;
        }
        if let Some(identity) = self.links.remove(&link.header.index) {
            identity.invalidate(Invalidation::Deleted);
        }
    }

    /// Notifications were lost: nothing captured so far can be proved.
    fn lose(&mut self) {
        for identity in self.links.values() {
            identity.invalidate(Invalidation::Lost);
        }
        self.links.clear();
        for watch in self.watches.drain(..) {
            if let Some(capture) = watch.capture.upgrade() {
                capture.lock().expect("creation watch poisoned").lost = true;
            }
        }
    }

    /// Returns false when the subscription can no longer prove continuity.
    fn message(&mut self, message: NetlinkMessage<RouteNetlinkMessage>) -> bool {
        match message.payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)) => self.new_link(link),
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(link)) => {
                self.delete_link(link)
            }
            NetlinkPayload::Overrun(_) | NetlinkPayload::Error(_) => {
                self.lose();
                return false;
            }
            _ => {}
        }
        true
    }
}

fn link_name(link: &LinkMessage) -> Option<&str> {
    link.attributes
        .iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::IfName(name) => Some(name.as_str()),
            _ => None,
        })
}

type Messages = BoxStream<'static, (NetlinkMessage<RouteNetlinkMessage>, SocketAddr)>;

struct Subscription {
    handle: rtnetlink::Handle,
    messages: Messages,
    driver: JoinHandle<()>,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl Subscription {
    async fn open() -> Result<(Self, Vec<LinkMessage>)> {
        let (connection, handle, messages) = crate::netlink::multicast_connection(
            &[MulticastGroup::Link],
            "session lifetime monitor",
            None,
        )
        .map_err(|e| {
            Error::Other(format!(
                "failed to subscribe to session device lifetimes: {e}"
            ))
        })?;
        let mut socket = Self {
            handle,
            messages: messages.boxed(),
            driver: tokio::spawn(connection),
        };
        let links = socket.dump().await?;
        Ok((socket, links))
    }

    async fn dump(&mut self) -> Result<Vec<LinkMessage>> {
        tokio::time::timeout(
            Duration::from_secs(5),
            self.handle.link().get().execute().try_collect(),
        )
        .await
        .map_err(|_| Error::Other("session device lifetime barrier timed out".into()))?
        .map_err(|e| {
            Error::Other(format!(
                "failed to synchronize session device lifetimes: {e}"
            ))
        })
    }

    async fn find(&mut self, index: u32) -> Result<Lookup> {
        let mut links = self.handle.link().get().match_index(index).execute();
        let Ok(result) = tokio::time::timeout(Duration::from_secs(5), links.try_next()).await
        else {
            return Ok(Lookup::Unanswered);
        };
        match result {
            Ok(Some(link)) => Ok(Lookup::Found(link)),
            Ok(None) => Ok(Lookup::Missing),
            Err(e)
                if super::is_netlink_errno(&e, libc::ENODEV)
                    || super::is_netlink_errno(&e, libc::ENXIO) =>
            {
                Ok(Lookup::Missing)
            }
            Err(e) => Err(Error::Other(format!(
                "failed to validate session device index {index}: {e}"
            ))),
        }
    }

    fn drain(&mut self, ledger: &mut Ledger) -> bool {
        loop {
            match self.messages.next().now_or_never() {
                Some(Some((message, address))) => {
                    if address.port_number() != 0 {
                        continue;
                    }
                    if !ledger.message(message) {
                        return false;
                    }
                }
                Some(None) => {
                    ledger.lose();
                    return false;
                }
                None => return true,
            }
        }
    }
}

/// The outcome of looking a device up on the subscription socket.
enum Lookup {
    Found(LinkMessage),
    Missing,
    /// No reply came within the timeout. The kernel drops a reply when the
    /// socket's queue is full, and such a queue has lost notifications too.
    Unanswered,
}

enum Command {
    Arm(String, oneshot::Sender<Result<CreationWatch>>),
    Finish(
        Arc<Mutex<Capture>>,
        Option<u32>,
        oneshot::Sender<Result<std::result::Result<LinkIdentity, Invalidation>>>,
    ),
    Validate(LinkIdentity, oneshot::Sender<Result<LinkStatus>>),
}

struct Worker {
    socket: Option<Subscription>,
    ledger: Ledger,
}

impl Worker {
    async fn ensure_socket(&mut self) -> Result<()> {
        if self.socket.is_none() {
            let (mut socket, links) = Subscription::open().await?;
            self.ledger.seed(links);
            if !socket.drain(&mut self.ledger) {
                return Err(Error::Other(
                    "session device lifetime subscription lost during initialization".into(),
                ));
            }
            self.socket = Some(socket);
        }
        Ok(())
    }

    fn drain(&mut self) {
        if let Some(socket) = self.socket.as_mut() {
            if !socket.drain(&mut self.ledger) {
                self.socket = None;
            }
        }
    }

    /// Looks a device up on the subscription, which also orders the lookup
    /// after every notification queued before it. A reply that never comes
    /// means the socket was congested, so its notifications are taken as
    /// lost and the subscription is reopened at the next use.
    async fn lookup(&mut self, index: u32) -> Result<Lookup> {
        let Some(socket) = self.socket.as_mut() else {
            return Ok(Lookup::Unanswered);
        };
        let result = socket.find(index).await;
        self.drain();
        if matches!(result, Ok(Lookup::Unanswered)) {
            log::warn!(
                "the session device lifetime subscription stopped answering; its link notifications are taken as lost"
            );
            self.ledger.lose();
            self.socket = None;
        }
        result
    }

    async fn barrier(&mut self) -> Result<()> {
        // A loss already queued is noticed now, rather than by waiting for
        // the reply an overflowed socket cannot deliver.
        self.drain();
        self.ensure_socket().await?;
        // Any indexed reply, including ENODEV, is an ordering barrier.
        // Only initialization needs a full dump to seed existing links.
        if matches!(self.lookup(1).await?, Lookup::Unanswered) || self.socket.is_none() {
            return Err(Error::Other(
                "session device lifetime subscription lost".into(),
            ));
        }
        Ok(())
    }

    async fn validate(&mut self, identity: LinkIdentity) -> Result<LinkStatus> {
        if let Some(why) = identity.invalidation() {
            return Ok(LinkStatus::Invalidated(why));
        }
        self.drain();
        if let Some(why) = identity.invalidation() {
            return Ok(LinkStatus::Invalidated(why));
        }
        if self.socket.is_none() {
            identity.invalidate(Invalidation::Lost);
            return Ok(LinkStatus::Invalidated(Invalidation::Lost));
        }
        let result = self.lookup(identity.index).await?;
        if let Some(why) = identity.invalidation() {
            return Ok(LinkStatus::Invalidated(why));
        }
        match result {
            Lookup::Found(link) => Ok(LinkStatus::Live(link)),
            Lookup::Missing => {
                identity.invalidate(Invalidation::Deleted);
                self.ledger.links.remove(&identity.index);
                Ok(LinkStatus::Invalidated(Invalidation::Deleted))
            }
            Lookup::Unanswered => {
                identity.invalidate(Invalidation::Lost);
                Ok(LinkStatus::Invalidated(Invalidation::Lost))
            }
        }
    }

    /// Identifies a creation after its capture was lost or disagreed with
    /// the registration index: the device at `index` is the one created if
    /// it still bears the creation name. Its ledger entry, seeded or
    /// inserted now, carries its lifetime from here on.
    async fn recover_creation(
        &mut self,
        index: u32,
        name: &str,
    ) -> Result<std::result::Result<LinkIdentity, Invalidation>> {
        match self.lookup(index).await? {
            Lookup::Found(link) if link_name(&link) == Some(name) => {
                log::info!(
                    "identified the interface created as {name} at index {index} by its name, link notifications having been lost"
                );
                Ok(Ok(self
                    .ledger
                    .links
                    .entry(index)
                    .or_insert_with(|| LinkIdentity::new(index))
                    .clone()))
            }
            _ => Ok(Err(Invalidation::Lost)),
        }
    }

    async fn command(&mut self, command: Command) {
        match command {
            Command::Arm(name, reply) => {
                let result = self.barrier().await.map(|()| self.ledger.arm(name));
                let _ = reply.send(result);
            }
            Command::Finish(capture, expected_index, reply) => {
                let result = self.barrier().await;
                let (first, name) = {
                    let capture = capture.lock().expect("creation watch poisoned");
                    (capture.first.clone(), capture.name.clone())
                };
                let result = match (result, first) {
                    (Err(error), _) => Err(error),
                    // The capture by name and the registration index agree.
                    (Ok(()), Some(identity))
                        if identity.is_live()
                            && expected_index.is_none_or(|index| index == identity.index) =>
                    {
                        Ok(Ok(identity))
                    }
                    // The registration broadcast named the index; the device
                    // there is the one created if it still has its name.
                    (Ok(()), _) => match expected_index {
                        Some(index) => self.recover_creation(index, &name).await,
                        None => Ok(Err(Invalidation::Lost)),
                    },
                };
                let _ = reply.send(result);
            }
            Command::Validate(identity, reply) => {
                let result = self.validate(identity).await;
                let _ = reply.send(result);
            }
        }
    }

    async fn run(mut self, mut commands: mpsc::Receiver<Command>) {
        loop {
            if let Some(socket) = self.socket.as_mut() {
                tokio::select! {
                    command = commands.recv() => {
                        let Some(command) = command else { break };
                        self.command(command).await;
                    }
                    message = socket.messages.next() => {
                        let healthy = match message {
                            Some((message, address)) => {
                                address.port_number() != 0 || self.ledger.message(message)
                            }
                            None => { self.ledger.lose(); false }
                        };
                        if !healthy { self.socket = None; }
                    }
                }
            } else {
                let Some(command) = commands.recv().await else {
                    break;
                };
                self.command(command).await;
            }
        }
        self.ledger.lose();
    }
}

pub(super) struct LinkIdentityMonitor {
    commands: mpsc::Sender<Command>,
    worker: JoinHandle<()>,
}

impl LinkIdentityMonitor {
    pub(super) async fn new() -> Result<Self> {
        let mut worker = Worker {
            socket: None,
            ledger: Ledger::default(),
        };
        worker.ensure_socket().await?;
        let (commands, receiver) = mpsc::channel(32);
        Ok(Self {
            commands,
            worker: tokio::spawn(worker.run(receiver)),
        })
    }

    pub(super) async fn arm_creation(&self, name: &L2tpIfName) -> Result<CreationWatch> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::Arm(name.to_string(), reply))
            .await
            .map_err(|_| monitor_closed())?;
        response.await.map_err(|_| monitor_closed())?
    }

    /// The identity of the device created under the armed name. The outer
    /// error is a netlink failure, worth retrying; the inner one means the
    /// creation cannot be identified any more.
    pub(super) async fn finish_creation(
        &self,
        watch: &CreationWatch,
        expected_index: Option<u32>,
    ) -> Result<std::result::Result<LinkIdentity, Invalidation>> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::Finish(
                watch.capture.clone(),
                expected_index,
                reply,
            ))
            .await
            .map_err(|_| monitor_closed())?;
        response.await.map_err(|_| monitor_closed())?
    }

    pub(super) async fn validate(&self, identity: &LinkIdentity) -> Result<LinkStatus> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::Validate(identity.clone(), reply))
            .await
            .map_err(|_| monitor_closed())?;
        response.await.map_err(|_| monitor_closed())?
    }
}

impl Drop for LinkIdentityMonitor {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

fn monitor_closed() -> Error {
    Error::Other("session device lifetime monitor stopped".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(index: u32, name: &str) -> LinkMessage {
        let mut link = LinkMessage::default();
        link.header.index = index;
        link.attributes
            .push(LinkAttribute::IfName(name.to_string()));
        link
    }

    fn captured(watch: &CreationWatch) -> LinkIdentity {
        watch
            .capture
            .lock()
            .unwrap()
            .first
            .clone()
            .expect("creation captured")
    }

    fn is_lost(watch: &CreationWatch) -> bool {
        watch.capture.lock().unwrap().lost
    }

    #[test]
    fn only_a_new_device_captures_creation_and_renames_preserve_identity() {
        let mut ledger = Ledger::default();
        ledger.seed([link(1, "existing")]);
        let watch = ledger.arm("session".into());
        ledger.new_link(link(1, "session"));
        assert!(watch.capture.lock().unwrap().first.is_none());
        ledger.new_link(link(2, "session"));
        let identity = captured(&watch);
        ledger.new_link(link(2, "renamed"));
        ledger.new_link(link(3, "child"));
        ledger.delete_link(link(3, "child"));
        assert!(identity.is_live());
        assert_eq!(identity.index(), 2);
    }

    #[test]
    fn deletion_and_index_reuse_never_adopt_a_replacement() {
        let mut ledger = Ledger::default();
        let watch = ledger.arm("session".into());
        ledger.new_link(link(2, "session"));
        let first = captured(&watch);
        ledger.delete_link(link(2, "session"));
        ledger.new_link(link(2, "session"));
        assert_eq!(first.invalidation(), Some(Invalidation::Deleted));
        assert_eq!(captured(&watch).invalidation(), Some(Invalidation::Deleted));
        assert!(ledger.links[&2].is_live());
        assert!(!is_lost(&watch));
        // A later loss cannot turn an observed deletion into a loss.
        ledger.lose();
        assert_eq!(first.invalidation(), Some(Invalidation::Deleted));
    }

    #[test]
    fn protocol_specific_deletion_is_not_netdevice_deletion() {
        let mut ledger = Ledger::default();
        let watch = ledger.arm("session".into());
        ledger.new_link(link(2, "session"));
        for family in [AddressFamily::Bridge, AddressFamily::Inet6] {
            let mut metadata = link(2, "session");
            metadata.header.interface_family = family;
            ledger.delete_link(metadata);
        }
        assert!(captured(&watch).is_live());
    }

    #[test]
    fn monitor_loss_invalidates_existing_and_uncaptured_watches() {
        let mut ledger = Ledger::default();
        let first = ledger.arm("session".into());
        let missing = ledger.arm("next".into());
        ledger.new_link(link(2, "session"));
        assert!(!ledger.message(NetlinkMessage::new(
            Default::default(),
            NetlinkPayload::Overrun(Vec::new()),
        )));
        ledger.seed([link(2, "session")]);
        ledger.new_link(link(3, "next"));
        assert_eq!(captured(&first).invalidation(), Some(Invalidation::Lost));
        assert!(is_lost(&first));
        assert!(is_lost(&missing));
        assert!(missing.capture.lock().unwrap().first.is_none());
        // The reseeded entry is a fresh, live identity.
        assert!(ledger.links[&2].is_live());
    }
}
