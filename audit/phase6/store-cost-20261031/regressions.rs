
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod cost_tests {
    use super::*;
    use crate::kernel::fake::FakeKernel;
    use crate::reconciler::IphostResolve;

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
            println!("STORE_ACK_COST unrelated={count} stale=500 elapsed_ns={}", started.elapsed().as_nanos());
            assert_eq!(r.store.retiring.len(), count);
            assert_eq!(r.store.next_deadline(r.k.now()), deadline);
            assert!(r.store.retiring.values().all(|record| record.pending.is_some() && !record.withdrawn));
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
        let request = r.take_requests().into_iter().find_map(|request| match request {
            Request::ForgetSocket { name, id, .. } if name == "t10" => Some(id),
            _ => None,
        }).unwrap();
        let unrelated = r.store.retiring["t20"].pending;
        // A single failed confirmation must consume only the first refusal.
        r.k.fail_next("tunnel", nix::errno::Errno::EIO);
        r.k.fail_next("tunnel", nix::errno::Errno::EIO);
        r.socket_forgotten(request, true);
        assert_eq!(r.k.tunnel(999).unwrap_err().raw_os_error(), Some(nix::libc::EIO));
        assert!(r.k.tunnel(999).unwrap().is_none());
        assert_eq!(r.store.retiring["t20"].pending, unrelated);
        assert!(r.store.retiring["t10"].withdrawn);
    }
}
