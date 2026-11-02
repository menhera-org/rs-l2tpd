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
    pending: BTreeMap<u64, (String, Instant)>,
    blocked: BTreeMap<u32, usize>,
    deadlines: super::deadlines::Deadlines<String>,
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
    closed: Option<Instant>,
}

impl<K: Kernel> Drop for Reconciler<K> {
    fn drop(&mut self) {
        for socket in self.tunnels.values().map(|record| record.socket).chain(
            self.store
                .retiring
                .values()
                .flat_map(|record| record.sockets.iter().copied()),
        ) {
            self.k.close(socket);
        }
    }
}

impl Store {
    pub fn retry_now(&mut self, now: Instant) {
        for name in self.retiring.keys() {
            self.deadlines.insert(name.clone(), now);
        }
    }

    pub fn next_deadline(&self, now: Instant) -> Option<Instant> {
        if self.shutdown.is_some_and(|deadline| now >= deadline) {
            return None;
        }
        self.deadlines
            .first_deadline()
            .into_iter()
            .chain(self.shutdown)
            .min()
    }

    pub fn blocks(&self, id: u32) -> bool {
        let name = format!("t{id}");
        self.inherited.contains_key(&name)
            || self.blocked.contains_key(&id)
            || self.retiring.contains_key(&name)
    }
}

impl<K: Kernel> Reconciler<K> {
    pub(crate) fn take_inherited(&mut self) -> Vec<(String, OwnedFd)> {
        std::mem::take(&mut self.store.inherited)
            .into_iter()
            .flat_map(|(name, fds)| fds.into_iter().map(move |fd| (name.clone(), fd)))
            .collect()
    }

    /// Announces descriptor-store capacity. Zero (the default) means no
    /// store; sockets remain locally owned. Set before reconciliation.
    pub fn set_store_capacity(&mut self, capacity: usize) {
        self.store.capacity = capacity;
    }

    // Only for a submission that could not reach the program; this synchronous
    // owner-thread path cannot reject a later incarnation of the same name.
    pub(crate) fn store_refused(&mut self, name: &str) {
        if !self.store.inherited.contains_key(name)
            && !self.store.retiring.contains_key(name)
            && self.store.names.remove(name)
        {
            log::warn!("{name}: storage unavailable; socket remains locally owned");
        }
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
                self.queue_request(Request::StoreSocket {
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
        self.cancel_stored_request(&name);
        let now = self.k.now();
        let r = self
            .store
            .retiring
            .entry(name.clone())
            .or_insert_with(|| Retirement {
                sockets: Vec::new(),
                fds: Vec::new(),
                ids: BTreeSet::new(),
                pending: None,
                withdrawn: self.store.capacity == 0,
                next: now,
                reported: false,
                closed: None,
            });
        r.sockets.extend(sockets);
        r.fds.extend(fds);
        if let Some(id) = id
            && r.ids.insert(id)
        {
            *self.store.blocked.entry(id).or_default() += 1;
        }
        self.store
            .deadlines
            .insert(name, r.pending.map_or(r.next, |(_, at)| at));
    }

    /// A withdrawal outcome. `processed` means the manager's processing
    /// barrier completed; a successful datagram send alone is `false`.
    /// Stale acknowledgements cannot release a later store submission.
    pub fn socket_forgotten(&mut self, id: u64, processed: bool) {
        let now = self.k.now();
        let Some((name, deadline)) = self.store.pending.get(&id).cloned() else {
            return;
        };
        if now >= deadline {
            return;
        }
        self.store.pending.remove(&id);
        let r = self.store.retiring.get_mut(&name).unwrap();
        r.pending = None;
        r.withdrawn = processed;
        r.next = now + RETRY;
        for socket in r.sockets.drain(..) {
            self.k.close(socket);
        }
        r.fds.clear();
        r.closed.get_or_insert(now);
        self.retire_socket(name);
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
                self.wanted_tunnels
                    .get(&id)
                    .map(|name| self.accepted.tunnels()[name].clone())
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
                                | nix::libc::ESOCKTNOSUPPORT
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
        let names: Vec<_> = if self.store.shutdown.is_some_and(|deadline| now >= deadline) {
            self.store.retiring.keys().cloned().collect()
        } else {
            self.store.deadlines.due(now).cloned().collect()
        };
        for name in names {
            self.retire_socket(name);
        }
    }

    fn retire_socket(&mut self, name: String) {
        let now = self.k.now();
        let stopping = self.store.shutdown.is_some_and(|deadline| now >= deadline);
        let r = self.store.retiring.get_mut(&name).unwrap();
        let expired = r.pending.is_some_and(|(_, deadline)| now >= deadline);
        if expired || stopping {
            if let Some((id, _)) = r.pending.take() {
                self.store.pending.remove(&id);
            }
            for socket in r.sockets.drain(..) {
                self.k.close(socket);
            }
            r.fds.clear();
            r.closed.get_or_insert(now);
            r.next = now + RETRY;
        }
        if r.withdrawn {
            for socket in r.sockets.drain(..) {
                self.k.close(socket);
            }
            r.fds.clear();
            r.closed.get_or_insert(now);
        }
        let absent = r.sockets.is_empty()
            && r.fds.is_empty()
            && r.ids
                .iter()
                .all(|id| matches!(self.k.tunnel(*id), Ok(None)));
        if r.withdrawn && absent {
            let removed = self.store.retiring.remove(&name).unwrap();
            for id in removed.ids {
                let count = self.store.blocked.get_mut(&id).unwrap();
                *count -= 1;
                if *count == 0 {
                    self.store.blocked.remove(&id);
                }
            }
            self.store.deadlines.remove(&name);
            self.store.names.remove(&name);
            return;
        }
        if stopping {
            if !r.reported
                && (!r.withdrawn || r.closed.is_none_or(|closed| now >= closed + DELETION_WAIT))
            {
                log::error!("descriptor store cleanup incomplete for {name}");
                r.reported = true;
            }
            self.store
                .deadlines
                .insert(name, r.pending.map_or(r.next, |(_, at)| at));
            return;
        }
        let request = if !r.withdrawn && r.pending.is_none() && now >= r.next {
            self.next_request += 1;
            let deadline = now + DELETION_WAIT;
            r.pending = Some((self.next_request, deadline));
            self.store
                .pending
                .insert(self.next_request, (name.clone(), deadline));
            Some(Request::ForgetSocket {
                name: name.clone(),
                id: self.next_request,
                deadline,
            })
        } else {
            None
        };
        if r.pending.is_none() && r.next <= now {
            r.next = now + RETRY;
        }
        self.store
            .deadlines
            .insert(name, r.pending.map_or(r.next, |(_, at)| at));
        if let Some(request) = request {
            self.queue_request(request);
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod cost_tests {
    use super::*;
    use crate::kernel::fake::FakeKernel;
    use crate::reconciler::IphostResolve;
    #[cfg(feature = "serde")]
    use nix::libc;

    /// spec: P14, L13, A10, G20
    #[cfg(feature = "serde")]
    #[test]
    fn inherited_verification_refuses_shutdown_and_an_existing_local_owner() {
        for shutting_down in [false, true] {
            let mut r = Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
            let config = toml::from_str("[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\n").unwrap();
            assert!(r.reconcile(config));
            let socket = r.tunnels[&10].socket;
            let connection = r.k.connection(socket);
            // Exercise the verifier's defensive state directly; public inherit is startup-only.
            r.store.names.insert("t10".into());
            r.store
                .inherited
                .insert("t10".into(), vec![r.k.clone_fd(socket).unwrap()]);
            if shutting_down {
                r.store.shutdown = Some(r.k.now() + DELETION_WAIT);
                r.k.fail_next("adopt", nix::errno::Errno::EIO);
            }
            r.k.clear_ops();
            r.verify_inherited();
            assert!(r.store.inherited.is_empty());
            assert_eq!(r.tunnels.len(), 1);
            assert_eq!(r.tunnels[&10].socket, socket);
            assert_eq!(r.k.connection(socket), connection);
            assert_eq!(r.store.retiring["t10"].fds.len(), 1);
            assert_eq!(
                r.store.retiring["t10"].sockets.len(),
                usize::from(!shutting_down)
            );
            assert!(r.take_requests().is_empty());
            assert!(r.k.ops().is_empty());
            if shutting_down {
                let fd = r.k.clone_fd(socket).unwrap();
                assert_eq!(r.k.adopt(fd).err().unwrap().raw_os_error(), Some(libc::EIO));
            }
        }
    }

    /// spec: P14, L13, G20, E12
    #[cfg(feature = "serde")]
    #[test]
    #[ignore = "serial syscall-fault profile: children inherit concurrent fake descriptors"]
    fn descriptor_duplication_failures_keep_local_or_inherited_ownership() {
        const CHILD: &str = "RS_L2TPD_STORE_DUPLICATION_FAULT";
        let Ok(case) = std::env::var(CHILD) else {
            for case in ["store", "inherit"] {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--ignored", "--exact", "reconciler::store::cost_tests::descriptor_duplication_failures_keep_local_or_inherited_ownership", "--nocapture"])
                    .env(CHILD, case).output().unwrap();
                assert!(output.status.success(), "{case}: {output:?}");
                assert!(
                    String::from_utf8_lossy(&output.stdout)
                        .contains("STORE_DUPLICATION_FAILURE_CHECKED=")
                );
                assert!(!String::from_utf8_lossy(&output.stderr).contains("LLVM Profile Error"));
                if case == "store" {
                    assert!(
                        String::from_utf8_lossy(&output.stderr)
                            .contains("cannot duplicate socket for storage")
                    );
                }
            }
            return;
        };
        let mut kernel = FakeKernel::new(42);
        let inherited = if case == "inherit" {
            let socket = kernel
                .create_socket(crate::config::Family::V6, 10, 10)
                .unwrap();
            kernel.register_tunnel(socket, 10, 10).unwrap();
            let fd = kernel.clone_fd(socket).unwrap();
            kernel.close(socket);
            Some(fd)
        } else {
            None
        };
        let mut r = Reconciler::new(kernel, Box::new(IphostResolve::default()));
        let config: crate::config::Config = toml::from_str(
            "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\n",
        )
        .unwrap();
        if let Some(fd) = inherited {
            r.inherit("t10".into(), fd);
        } else {
            assert!(r.reconcile(config.clone()));
            r.set_store_capacity(1);
        }
        crate::kernel::linux::syscall_fault::log_warnings();
        crate::kernel::linux::syscall_fault::on_exec_argument(
            libc::SYS_fcntl,
            1,
            libc::F_DUPFD_CLOEXEC as u32,
            libc::EMFILE,
        )()
        .unwrap();
        if case == "inherit" {
            assert!(!r.reconcile(config));
            assert_eq!(r.store.inherited["t10"].len(), 1);
            assert!(r.store.names.contains("t10"));
            assert!(r.tunnels.is_empty());
            assert!(r.k.tunnel(10).unwrap().is_some());
        } else {
            let socket = r.tunnels[&10].socket;
            r.store_socket(10, socket);
            assert!(r.store.names.is_empty());
            assert!(r.ready());
            assert_eq!(r.k.open_sockets(), 1);
            assert!(r.k.tunnel(10).unwrap().is_some());
        }
        assert!(r.take_requests().is_empty());
        println!("STORE_DUPLICATION_FAILURE_CHECKED={case}");
    }

    /// spec: P14, S28, L13, G20
    #[cfg(feature = "serde")]
    #[test]
    fn duplicate_unwanted_and_mismatched_inheritance_is_retired_before_creation() {
        for case in ["duplicate", "unwanted", "peer"] {
            let mut kernel = FakeKernel::new(42);
            let socket = kernel
                .create_socket(crate::config::Family::V6, 10, 20)
                .unwrap();
            kernel.register_tunnel(socket, 10, 20).unwrap();
            let fd = kernel.clone_fd(socket).unwrap();
            let duplicate = (case == "duplicate").then(|| kernel.clone_fd(socket).unwrap());
            kernel.close(socket);
            let mut r = Reconciler::new(kernel, Box::new(IphostResolve::default()));
            r.set_store_capacity(1);
            r.inherit("t10".into(), fd);
            if let Some(fd) = duplicate {
                r.inherit("t10".into(), fd);
            }
            let config = if case == "unwanted" {
                crate::config::Config::new()
            } else {
                toml::from_str("[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\n").unwrap()
            };
            // An ambiguous or unwanted announcement must not be inspected.
            if case != "peer" {
                r.k.fail_next("adopt", nix::errno::Errno::EIO);
            }
            r.reconcile(config);
            assert!(r.tunnels.is_empty(), "{case}");
            assert!(r.store.inherited.is_empty());
            assert_eq!(r.store.retiring.len(), 1);
            assert!(r.store.blocks(10));
            let requests = r.take_requests();
            assert!(
                matches!(requests.as_slice(), [Request::ForgetSocket { name, .. }] if name == "t10")
            );
            if case != "peer" {
                assert_eq!(
                    r.k.adopt(std::fs::File::open("/dev/null").unwrap().into())
                        .unwrap_err()
                        .raw_os_error(),
                    Some(libc::EIO)
                );
            }
            assert!(
                r.k.tunnel(10).unwrap().is_some(),
                "{case}: ownership must survive until withdrawal"
            );
        }
    }

    /// spec: P14, L13, G20
    #[test]
    fn submission_refusals_preserve_inherited_and_retiring_authority() {
        let mut r = Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
        let fd = std::fs::File::open("/dev/null").unwrap().into();
        r.inherit("t10".into(), fd);
        r.retirement("t20".into(), Vec::new(), Vec::new(), Some(20));
        r.store.names.insert("t20".into());
        r.store.names.insert("t30".into());
        for name in ["t10", "t20", "t30", "absent"] {
            r.store_refused(name);
        }
        assert_eq!(r.store.names, BTreeSet::from(["t10".into(), "t20".into()]));
        assert_eq!(r.store.inherited["t10"].len(), 1);
        assert!(r.store.retiring.contains_key("t20"));
        assert!(r.store.blocks(10));
        assert!(r.store.blocks(20));
        assert!(!r.store.blocks(30));
        assert!(r.take_requests().is_empty());
    }

    /// spec: P14, G20, L13
    #[test]
    fn storing_the_same_socket_twice_keeps_one_submission() {
        let mut r = Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
        let socket =
            r.k.create_socket(crate::config::Family::V6, 10, 10)
                .unwrap();
        r.set_store_capacity(2);
        r.store_socket(10, socket);
        assert_eq!(r.take_requests().len(), 1);
        r.store_socket(10, socket);
        assert!(r.take_requests().is_empty());
        assert_eq!(r.store.names, BTreeSet::from(["t10".into()]));
        assert_eq!(r.k.open_sockets(), 1);
        r.k.close(socket);
    }

    fn assert_indexes(r: &Reconciler<FakeKernel>) {
        let expected: BTreeMap<_, _> = r
            .store
            .retiring
            .iter()
            .filter_map(|(name, record)| {
                record
                    .pending
                    .map(|(id, deadline)| (id, (name.clone(), deadline)))
            })
            .collect();
        assert_eq!(r.store.pending, expected);
        let mut blocked = BTreeMap::new();
        for record in r.store.retiring.values() {
            for id in &record.ids {
                *blocked.entry(*id).or_default() += 1_usize;
            }
        }
        assert_eq!(r.store.blocked, blocked);
        assert_eq!(r.store.deadlines.len(), r.store.retiring.len());
    }

    /// spec: L12, L13, G23, M6, M16
    #[test]
    fn named_host_requests_coalesce_without_history_and_preserve_delivery_order() {
        use std::io::Read;
        let mut r = Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
        let deadline = r.k.now() + DELETION_WAIT;
        r.queue_request(Request::WriteBindv6only { id: 1, deadline });
        let (first, mut first_peer) = std::os::unix::net::UnixStream::pair().unwrap();
        r.queue_request(Request::StoreSocket {
            name: "t1".into(),
            tunnel_id: 1,
            fd: first.into(),
        });
        let (second, mut second_peer) = std::os::unix::net::UnixStream::pair().unwrap();
        r.queue_request(Request::StoreSocket {
            name: "t2".into(),
            tunnel_id: 2,
            fd: second.into(),
        });
        r.cancel_stored_request("t1");
        assert_eq!(first_peer.read(&mut [0]).unwrap(), 0);
        r.queue_request(Request::ForgetSocket {
            name: "t2".into(),
            id: 10,
            deadline,
        });
        assert_eq!(second_peer.read(&mut [0]).unwrap(), 0);
        for id in 20..1020 {
            r.queue_request(Request::ForgetSocket {
                name: "t1".into(),
                id,
                deadline,
            });
            assert_eq!(r.requests.len(), 3);
            assert_eq!(r.request_names.len(), 2);
        }
        r.cancel_stored_request("t2");
        r.cancel_stored_request("missing");
        assert!(r.shutdown());
        let delivered: Vec<_> = r
            .take_requests()
            .into_iter()
            .map(|request| match request {
                Request::ForgetSocket { name, id, .. } => (name, id),
                _ => panic!("shutdown must cancel the tunable request"),
            })
            .collect();
        assert_eq!(delivered, [("t2".into(), 10), ("t1".into(), 1019)]);
        assert!(r.requests.is_empty());
        assert!(r.request_names.is_empty());
    }

    /// spec: L13, G23, M16
    #[test]
    fn completed_retirement_history_releases_acknowledgement_and_identifier_indexes() {
        let mut r = Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
        r.set_store_capacity(1000);
        r.retirement("anchor".into(), Vec::new(), Vec::new(), Some(77));
        r.retire_sockets();
        r.take_requests();
        let anchor = r.store.retiring["anchor"].pending;
        r.retirement("anchor".into(), Vec::new(), Vec::new(), Some(77));
        assert_eq!(r.store.blocked[&77], 1);
        for (epoch, count) in [1, 300, 300, 1].into_iter().enumerate() {
            for n in 0..count {
                r.retirement(
                    format!("alias{epoch}_{n}"),
                    Vec::new(),
                    Vec::new(),
                    Some(77),
                );
            }
            r.retire_sockets();
            assert_indexes(&r);
            assert_eq!(r.store.blocked[&77], count + 1);
            let requests = r.take_requests();
            assert_eq!(requests.len(), count);
            for request in requests {
                let Request::ForgetSocket { id, .. } = request else {
                    panic!("unexpected request")
                };
                r.socket_forgotten(id, true);
                assert_indexes(&r);
            }
            assert_eq!(r.store.retiring.len(), 1);
            assert_eq!(r.store.pending.len(), 1);
            assert_eq!(r.store.blocked, BTreeMap::from([(77, 1)]));
            assert_eq!(r.store.retiring["anchor"].pending, anchor);
            println!("STORE_HISTORY epoch={epoch} retired={count} survivors=1");
        }
        r.socket_forgotten(anchor.unwrap().0, true);
        assert_indexes(&r);
        assert!(r.store.retiring.is_empty());
        assert!(r.store.pending.is_empty());
        assert!(r.store.blocked.is_empty());
        assert_eq!(r.store.next_deadline(r.k.now()), None);
    }

    /// spec: L13, M14, G23
    #[test]
    fn expired_and_refused_acknowledgements_keep_only_the_current_incarnation() {
        let mut r = Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
        r.set_store_capacity(1);
        r.retirement("t77".into(), Vec::new(), Vec::new(), Some(77));
        r.retire_sockets();
        r.take_requests();
        let first = r.store.retiring["t77"].pending.unwrap().0;
        r.k.advance(DELETION_WAIT);
        r.socket_forgotten(first, true);
        assert!(!r.store.retiring["t77"].withdrawn);
        assert_indexes(&r);
        r.retire_sockets();
        assert!(r.store.pending.is_empty());
        assert_indexes(&r);
        r.k.advance(RETRY);
        r.retire_sockets();
        r.take_requests();
        let second = r.store.retiring["t77"].pending.unwrap().0;
        assert_ne!(first, second);
        r.socket_forgotten(first, true);
        assert_eq!(r.store.retiring["t77"].pending.unwrap().0, second);
        r.socket_forgotten(second, false);
        assert!(!r.store.retiring["t77"].withdrawn);
        assert_indexes(&r);
        r.k.advance(RETRY);
        r.retire_sockets();
        r.take_requests();
        let third = r.store.retiring["t77"].pending.unwrap().0;
        r.socket_forgotten(third, true);
        assert_indexes(&r);
        assert!(r.store.retiring.is_empty());
    }

    /// spec: M16, G12, G23, L13
    #[test]
    fn stale_acknowledgement_cost_with_unrelated_retirements() {
        for count in [1, 300, 20_000] {
            let mut r = Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
            r.set_store_capacity(count);
            for n in 0..count {
                r.retirement(format!("unused{n}"), Vec::new(), Vec::new(), None);
            }
            r.retire_sockets();
            assert_eq!(r.take_requests().len(), count);
            let deadline = r.store.next_deadline(r.k.now());
            let started = Instant::now();
            for id in u64::try_from(count).unwrap() + 1..=u64::try_from(count).unwrap() + 500 {
                r.socket_forgotten(id, true);
            }
            println!(
                "STORE_ACK_COST unrelated={count} stale=500 elapsed_ns={}",
                started.elapsed().as_nanos()
            );
            assert_eq!(r.store.retiring.len(), count);
            assert_eq!(r.store.next_deadline(r.k.now()), deadline);
            assert!(
                r.store
                    .retiring
                    .values()
                    .all(|record| record.pending.is_some() && !record.withdrawn)
            );
            assert!(r.take_requests().is_empty());
            assert!(r.k.ops().is_empty());
        }
    }

    /// spec: M16, G12, L13
    #[test]
    fn a_processing_barrier_queries_only_its_own_retiring_tunnel() {
        let mut r = Reconciler::new(FakeKernel::new(42), Box::new(IphostResolve::default()));
        r.set_store_capacity(2);
        r.retirement("t10".into(), Vec::new(), Vec::new(), Some(10));
        r.retirement("t20".into(), Vec::new(), Vec::new(), Some(20));
        r.retire_sockets();
        let request = r
            .take_requests()
            .into_iter()
            .find_map(|request| match request {
                Request::ForgetSocket { name, id, .. } if name == "t10" => Some(id),
                _ => None,
            })
            .unwrap();
        let unrelated = r.store.retiring["t20"].pending;
        // A single failed confirmation must consume only the first refusal.
        r.k.fail_next("tunnel", nix::errno::Errno::EIO);
        r.k.fail_next("tunnel", nix::errno::Errno::EIO);
        r.socket_forgotten(request, true);
        assert_eq!(
            r.k.tunnel(999).unwrap_err().raw_os_error(),
            Some(nix::libc::EIO)
        );
        assert!(r.k.tunnel(999).unwrap().is_none());
        assert_eq!(r.store.retiring["t20"].pending, unrelated);
        assert!(r.store.retiring["t10"].withdrawn);
    }
}
