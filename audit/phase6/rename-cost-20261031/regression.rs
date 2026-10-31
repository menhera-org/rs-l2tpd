
/// spec: S11, S17, M6, M16, G2, G4, G23
#[test]
fn long_reverse_chains_and_cycles_preserve_devices_in_one_reconcile() {
    for count in [1, 100, 300] {
        for cycle in [false, true] {
            let document = |changed: bool| {
                let mut text = TUNNEL.to_owned();
                for n in 0..count {
                    let target = if !changed { n } else if cycle { (n + 1) % count } else { n + 1 };
                    text += &format!("\n[sessions.s{n:04}]\ntunnel_name='a'\nsession_id={}\ninterface_name='n{target}'\n", 1000 + n);
                }
                config(&text)
            };
            let (mut r, _) = reconciler();
            assert!(r.reconcile(document(false)));
            let before: Vec<_> = (0..count).map(|n| r.kernel().session_index(10, 1000 + n).unwrap()).collect();
            ops(&mut r);
            let changed = document(true);
            let started = std::time::Instant::now();
            assert!(r.reconcile(changed));
            let elapsed = started.elapsed();
            let changes = ops(&mut r);
            assert!(!changes.iter().any(|op| op.starts_with("create ") || op.starts_with("delete ") || op.starts_with("close ")));
            if !cycle { assert!(!changes.iter().any(|op| op.contains("rsl2tp-r"))); }
            for (n, device) in before.into_iter().enumerate() {
                let n = u32::try_from(n).unwrap();
                let target = if cycle { (n + 1) % count } else { n + 1 };
                assert_eq!(r.kernel().session_index(10, 1000 + n), Some(device));
                assert_eq!(r.kernel().link(device).unwrap().name().to_string_lossy(), format!("n{target}"));
            }
            println!("RENAME_COST sessions={count} cycle={cycle} elapsed_ns={} renames={}", elapsed.as_nanos(), changes.iter().filter(|op| op.starts_with("rename ")).count());
        }
    }
}
