//! Descriptor ownership and bounded retirement (P14, L13). The embedding
//! program performs withdrawals and reports a processing barrier, not a send.

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::OwnedFd;
use std::time::Instant;

use super::{DELETION_WAIT, RETRY, Reconciler, Request};
use crate::kernel::{Kernel, SocketId};

#[derive(Default)]
pub(super) struct Store {
    capacity: usize,
    names: BTreeSet<String>,
    inherited: BTreeMap<String, Vec<OwnedFd>>,
    pub retiring: BTreeMap<String, Retirement>,
    pub shutdown: Option<Instant>,
}

pub(super) struct Retirement {
    sockets: Vec<SocketId>,
    fds: Vec<OwnedFd>,
    ids: BTreeSet<u32>,
    pending: Option<(u64, Instant)>,
    withdrawn: bool,
    next: Instant,
    reported: bool,
}

impl Store {
    pub fn next_deadline(&self, now: Instant) -> Option<Instant> {
        if self.shutdown.is_some_and(|deadline| now >= deadline) {
            return None;
        }
        self.retiring
            .values()
            .map(|r| r.pending.map_or(r.next, |(_, d)| d))
            .chain(self.shutdown)
            .min()
    }

    pub fn blocks(&self, id: u32) -> bool {
        let name = format!("t{id}");
        self.inherited.contains_key(&name)
            || self.retiring.values().any(|r| r.ids.contains(&id))
            || self.retiring.contains_key(&name)
    }
}

impl<K: Kernel> Reconciler<K> {
    /// Announces descriptor-store capacity. Zero (the default) means no
    /// store; sockets remain locally owned. Set before reconciliation.
    pub fn set_store_capacity(&mut self, capacity: usize) {
        self.store.capacity = capacity;
    }

    /// Retains an inherited descriptor and its exact store name until
    /// bounded verification or retirement completes (P14). Call before
    /// the first reconcile; malformed names are withdrawn without inspection.
    pub fn inherit(&mut self, name: String, fd: OwnedFd) {
        self.store.names.insert(name.clone());
        self.store.inherited.entry(name).or_default().push(fd);
    }

    pub(super) fn store_socket(&mut self, id: u32, socket: SocketId) {
        let name = format!("t{id}");
        if self.store.capacity == 0 || self.store.names.contains(&name) {
            return;
        }
        if self.store.names.len() >= self.store.capacity {
            log::warn!("tunnel_id={id}: descriptor store full; socket remains locally owned");
            return;
        }
        match self.k.clone_fd(socket) {
            Ok(fd) => {
                self.store.names.insert(name.clone());
                self.requests.push(Request::StoreSocket {
                    tunnel_id: id,
                    name,
                    fd,
                });
            }
            Err(error) => {
                log::warn!("tunnel_id={id}: cannot duplicate socket for storage: {error}")
            }
        }
    }

    pub(super) fn withdraw_socket(&mut self, id: u32, socket: SocketId) -> bool {
        let name = format!("t{id}");
        if !self.store.names.contains(&name) {
            return false;
        }
        self.retirement(name, vec![socket], Vec::new(), Some(id));
        true
    }

    fn retirement(
        &mut self,
        name: String,
        sockets: Vec<SocketId>,
        fds: Vec<OwnedFd>,
        id: Option<u32>,
    ) {
        self.requests.retain(
            |r| !matches!(r, Request::StoreSocket { name: pending, .. } if pending == &name),
        );
        let now = self.k.now();
        let r = self
            .store
            .retiring
            .entry(name)
            .or_insert_with(|| Retirement {
                sockets: Vec::new(),
                fds: Vec::new(),
                ids: BTreeSet::new(),
                pending: None,
                withdrawn: self.store.capacity == 0,
                next: now,
                reported: false,
            });
        r.sockets.extend(sockets);
        r.fds.extend(fds);
        r.ids.extend(id);
    }

    /// A withdrawal outcome. `processed` means the manager's processing
    /// barrier completed; a successful datagram send alone is `false`.
    /// Stale acknowledgements cannot release a later store submission.
    pub fn socket_forgotten(&mut self, id: u64, processed: bool) {
        let now = self.k.now();
        for r in self.store.retiring.values_mut() {
            if r.pending
                .is_some_and(|(pending, deadline)| pending == id && now < deadline)
            {
                r.pending = None;
                r.withdrawn = processed;
                r.next = now + RETRY;
                for socket in r.sockets.drain(..) {
                    self.k.close(socket);
                }
                r.fds.clear();
                self.retire_sockets();
                return;
            }
        }
    }

    pub(super) fn verify_inherited(&mut self) {
        let names: Vec<_> = self.store.inherited.keys().cloned().collect();
        for name in names {
            let id = name
                .strip_prefix('t')
                .and_then(|s| s.parse::<u32>().ok())
                .filter(|id| name == format!("t{id}"));
            let mut fds = self.store.inherited.remove(&name).unwrap();
            let wanted = id.and_then(|id| {
                self.accepted
                    .tunnels()
                    .values()
                    .find(|t| t.tunnel_id() == id)
                    .cloned()
            });
            if fds.len() != 1 || wanted.is_none() || self.store.shutdown.is_some() {
                self.retirement(name, Vec::new(), fds, id);
                continue;
            }
            let fd = fds.pop().unwrap();
            let duplicate = match fd.try_clone() {
                Ok(duplicate) => duplicate,
                Err(_) => {
                    self.store.inherited.insert(name, vec![fd]);
                    self.incomplete = true;
                    continue;
                }
            };
            match self.k.adopt(duplicate) {
                Ok(adopted)
                    if adopted.tunnel_id == id.unwrap()
                        && adopted.peer_tunnel_id == wanted.as_ref().unwrap().peer_tunnel_id()
                        && !self.tunnels.contains_key(&adopted.tunnel_id) =>
                {
                    match self.record_adopted(adopted) {
                        Ok(()) => {}
                        Err(error) => {
                            // The dump may have failed; retain ownership and retry.
                            self.k.close(adopted.socket);
                            self.store.inherited.insert(name, vec![fd]);
                            self.incomplete = true;
                            log::warn!("inherited socket verification: {error}");
                        }
                    }
                }
                Ok(adopted) => self.retirement(
                    name,
                    vec![adopted.socket],
                    vec![fd],
                    Some(adopted.tunnel_id),
                ),
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(
                            nix::libc::EINVAL
                                | nix::libc::ENOTSOCK
                                | nix::libc::EAFNOSUPPORT
                                | nix::libc::EPROTONOSUPPORT
                                | nix::libc::ENODEV
                        )
                    ) =>
                {
                    self.retirement(name, Vec::new(), vec![fd], id);
                }
                Err(error) => {
                    self.store.inherited.insert(name, vec![fd]);
                    self.incomplete = true;
                    log::debug!("inherited socket verification is uncertain: {error}");
                }
            }
        }
    }

    pub(super) fn retire_sockets(&mut self) {
        let now = self.k.now();
        let stopping = self.store.shutdown.is_some_and(|deadline| now >= deadline);
        let names: Vec<_> = self.store.retiring.keys().cloned().collect();
        for name in names {
            let r = self.store.retiring.get_mut(&name).unwrap();
            let expired = r.pending.is_some_and(|(_, deadline)| now >= deadline);
            if expired || stopping {
                r.pending = None;
                for socket in r.sockets.drain(..) {
                    self.k.close(socket);
                }
                r.fds.clear();
                r.next = now + RETRY;
            }
            if r.withdrawn {
                for socket in r.sockets.drain(..) {
                    self.k.close(socket);
                }
                r.fds.clear();
            }
            let absent = r.sockets.is_empty()
                && r.fds.is_empty()
                && r.ids
                    .iter()
                    .all(|id| matches!(self.k.tunnel(*id), Ok(None)));
            if r.withdrawn && absent {
                self.store.retiring.remove(&name);
                self.store.names.remove(&name);
                continue;
            }
            if stopping {
                if !r.reported {
                    log::error!("descriptor store cleanup incomplete for {name}");
                    r.reported = true;
                }
                continue;
            }
            if !r.withdrawn && r.pending.is_none() && now >= r.next {
                self.next_request += 1;
                let deadline = now + DELETION_WAIT;
                r.pending = Some((self.next_request, deadline));
                self.requests.retain(|r| !matches!(r, Request::ForgetSocket { name: pending, .. } if pending == &name));
                self.requests.push(Request::ForgetSocket {
                    name,
                    id: self.next_request,
                    deadline,
                });
            }
            if r.pending.is_none() && r.next <= now {
                r.next = now + RETRY;
            }
        }
    }
}
