//! Tracks netdevice lifetimes separately from their reusable names and indices.
//!
//! The subscription starts before session creation. Before a mutation, a
//! GETLINK response on that same socket and a drain of earlier notifications
//! detect deletion, namespace moves, and index reuse. Linux does not provide an
//! atomic lifetime-token-plus-SETLINK operation: callers must still keep the
//! interval between validation and mutation short.

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
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, Weak,
    },
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

#[derive(Clone)]
pub(super) struct LinkIdentity {
    index: u32,
    live: Arc<AtomicBool>,
}

impl LinkIdentity {
    pub(super) fn index(&self) -> u32 {
        self.index
    }

    fn is_live(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }

    fn invalidate(&self) {
        self.live.store(false, Ordering::Release);
    }
}

#[derive(Default)]
struct Capture {
    first: Option<LinkIdentity>,
    invalidated: bool,
}

pub(super) struct CreationWatch {
    capture: Arc<Mutex<Capture>>,
}

impl CreationWatch {
    pub(super) fn is_invalidated(&self) -> bool {
        let capture = self.capture.lock().expect("creation watch poisoned");
        capture.invalidated || capture.first.as_ref().is_some_and(|id| !id.is_live())
    }
}

pub(super) enum LinkStatus {
    Live(LinkMessage),
    Invalidated,
}

struct PendingWatch {
    name: String,
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
                .or_insert_with(|| LinkIdentity {
                    index: link.header.index,
                    live: Arc::new(AtomicBool::new(true)),
                });
        }
    }

    fn arm(&mut self, name: String) -> CreationWatch {
        self.watches
            .retain(|watch| watch.capture.strong_count() != 0);
        let capture = Arc::new(Mutex::new(Capture::default()));
        self.watches.push(PendingWatch {
            name,
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
        let identity = LinkIdentity {
            index: link.header.index,
            live: Arc::new(AtomicBool::new(true)),
        };
        let name = link
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                LinkAttribute::IfName(name) => Some(name),
                _ => None,
            });
        self.watches.retain(|watch| {
            let Some(capture) = watch.capture.upgrade() else {
                return false;
            };
            let mut capture = capture.lock().expect("creation watch poisoned");
            if !capture.invalidated && capture.first.is_none() && name == Some(&watch.name) {
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
            identity.invalidate();
        }
    }

    fn invalidate(&mut self) {
        for identity in self.links.values() {
            identity.invalidate();
        }
        self.links.clear();
        for watch in self.watches.drain(..) {
            if let Some(capture) = watch.capture.upgrade() {
                capture.lock().expect("creation watch poisoned").invalidated = true;
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
                self.invalidate();
                return false;
            }
            _ => {}
        }
        true
    }
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

    async fn find(&mut self, index: u32) -> Result<Option<LinkMessage>> {
        let mut links = self.handle.link().get().match_index(index).execute();
        let result = tokio::time::timeout(Duration::from_secs(5), links.try_next())
            .await
            .map_err(|_| Error::Other("session device lookup timed out".into()))?;
        match result {
            Ok(link) => Ok(link),
            Err(e)
                if super::is_netlink_errno(&e, libc::ENODEV)
                    || super::is_netlink_errno(&e, libc::ENXIO) =>
            {
                Ok(None)
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
                    ledger.invalidate();
                    return false;
                }
                None => return true,
            }
        }
    }
}

enum Command {
    Arm(String, oneshot::Sender<Result<CreationWatch>>),
    Finish(
        Arc<Mutex<Capture>>,
        Option<u32>,
        oneshot::Sender<Result<LinkIdentity>>,
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

    async fn barrier(&mut self) -> Result<()> {
        self.ensure_socket().await?;
        let result = self
            .socket
            .as_mut()
            .expect("subscription exists")
            // Any indexed reply, including ENODEV, is an ordering barrier.
            // Only initialization needs a full dump to seed existing links.
            .find(1)
            .await
            .map(|_| ());
        self.drain();
        result?;
        if self.socket.is_none() {
            return Err(Error::Other(
                "session device lifetime subscription lost".into(),
            ));
        }
        Ok(())
    }

    async fn validate(&mut self, identity: LinkIdentity) -> Result<LinkStatus> {
        if !identity.is_live() {
            return Ok(LinkStatus::Invalidated);
        }
        let Some(socket) = self.socket.as_mut() else {
            identity.invalidate();
            return Ok(LinkStatus::Invalidated);
        };
        let result = socket.find(identity.index).await;
        self.drain();
        if !identity.is_live() {
            return Ok(LinkStatus::Invalidated);
        }
        match result? {
            Some(link) => Ok(LinkStatus::Live(link)),
            None => {
                identity.invalidate();
                self.ledger.links.remove(&identity.index);
                Ok(LinkStatus::Invalidated)
            }
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
                let capture = capture.lock().expect("creation watch poisoned");
                let result = if let Some(identity) = &capture.first {
                    if expected_index.is_some_and(|index| index != identity.index) {
                        Err(Error::Other(
                            "session creation index differs from its observed lifetime".into(),
                        ))
                    } else {
                        // Return an invalidated first capture as well, so cleanup
                        // can explicitly skip a now-unprovable session ID.
                        Ok(identity.clone())
                    }
                } else {
                    result.and_then(|()| {
                        Err(Error::Other(
                        if capture.invalidated {
                            "session device lifetime was lost before creation could be identified"
                        } else {
                            "session device creation has not been observed"
                        }.into()
                    ))
                    })
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
                            None => { self.ledger.invalidate(); false }
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
        self.ledger.invalidate();
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

    pub(super) async fn finish_creation(
        &self,
        watch: &CreationWatch,
        expected_index: Option<u32>,
    ) -> Result<LinkIdentity> {
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
        assert!(!first.is_live());
        assert!(!captured(&watch).is_live());
        assert!(ledger.links[&2].is_live());
        assert!(watch.is_invalidated());
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
        assert!(first.is_invalidated());
        assert!(missing.is_invalidated());
        assert!(missing.capture.lock().unwrap().first.is_none());
    }
}
