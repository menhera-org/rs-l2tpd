//! The behavioural rules over the fake kernel (docs/testing.md), one
//! module per specification page. No test sleeps: time is the fake's.
//! Phase 3 is in progress: only the first cases exist so far.

mod sessions;
mod tunnels;

use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rs_l2tpd::config::Config;
use rs_l2tpd::kernel::fake::FakeKernel;
use rs_l2tpd::reconciler::{Lookup, Reconciler, Resolve};

/// A configuration from TOML, strictly (C15).
pub fn config(text: &str) -> Config {
    toml::from_str(text).unwrap()
}

#[derive(Default)]
struct Lookups {
    watching: BTreeMap<u64, Lookup>,
    results: Vec<(u64, Vec<IpAddr>)>,
    refuse: bool,
}

/// The test's side of the lookups: it answers host names when it likes.
#[derive(Clone, Default)]
pub struct Answers(Arc<Mutex<Lookups>>);

impl Answers {
    /// Delivers an answer to every lookup of `host` now watched.
    pub fn answer(&self, host: &str, addrs: &[&str]) {
        let mut state = self.0.lock().unwrap();
        let ids: Vec<u64> = state
            .watching
            .iter()
            .filter(|(_, l)| l.host == host)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            state
                .results
                .push((id, addrs.iter().map(|a| a.parse().unwrap()).collect()));
        }
    }

    /// The lookups now watched.
    pub fn watching(&self) -> Vec<Lookup> {
        self.0.lock().unwrap().watching.values().cloned().collect()
    }

    /// Makes the next watches fail, as a refused port would (V12).
    pub fn refuse(&self, refuse: bool) {
        self.0.lock().unwrap().refuse = refuse;
    }
}

impl Resolve for Answers {
    fn watch(&mut self, lookup: Lookup) -> io::Result<()> {
        let mut state = self.0.lock().unwrap();
        if state.refuse {
            return Err(io::Error::from_raw_os_error(nix::libc::EADDRINUSE));
        }
        state.watching.insert(lookup.id, lookup);
        Ok(())
    }
    fn unwatch(&mut self, id: u64) {
        self.0.lock().unwrap().watching.remove(&id);
    }
    fn poll(&mut self) -> Vec<(u64, Vec<IpAddr>)> {
        std::mem::take(&mut self.0.lock().unwrap().results)
    }
}

/// A reconciler over a fresh fake namespace.
pub fn reconciler() -> (Reconciler<FakeKernel>, Answers) {
    let answers = Answers::default();
    (
        Reconciler::new(FakeKernel::new(42), Box::new(answers.clone())),
        answers,
    )
}

/// Advances the clock by `secs` seconds one at a time, ticking, as the
/// runtime does.
pub fn run_for(r: &mut Reconciler<FakeKernel>, secs: u64) {
    for _ in 0..secs {
        r.kernel_mut().advance(Duration::from_secs(1));
        r.kernel_mut().tick();
        r.tick();
    }
}

/// Feeds every queued notice of the fake to the reconciler, as the
/// runtime's subscription tasks do.
pub fn deliver(r: &mut Reconciler<FakeKernel>) {
    use rs_l2tpd::reconciler::Source;
    loop {
        let monitor = r.kernel_mut().take_monitor();
        let l2tp = r.kernel_mut().take_l2tp();
        if monitor.is_empty() && l2tp.is_empty() {
            return;
        }
        for n in monitor {
            r.handle(Source::Monitor, n);
        }
        for n in l2tp {
            r.handle(Source::L2tp, n);
        }
    }
}

/// The operations issued since the last call.
pub fn ops(r: &mut Reconciler<FakeKernel>) -> Vec<String> {
    let ops = r.kernel().ops().to_vec();
    r.kernel_mut().clear_ops();
    ops
}

pub const TUNNEL: &str = r#"
[tunnels.a]
tunnel_id = 10
peer_tunnel_id = 20
remote_addr = "192.0.2.2"
"#;
