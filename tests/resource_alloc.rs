//! Allocation-visible transient inventory bounds; the fake host predates measurement.
use rs_l2tpd::kernel::{Notice, fake::FakeKernel};

use rs_l2tpd::reconciler::{IphostResolve, Reconciler, Source};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Duration;

struct Meter;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn allocated(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Relaxed) + bytes;
    PEAK.fetch_max(live, Relaxed);
}

// SAFETY: pointers/layouts are forwarded unchanged; only successful allocations count.
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        LIVE.fetch_sub(layout.size(), Relaxed);
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let replacement = unsafe { System.realloc(pointer, layout, size) };
        if !replacement.is_null() {
            LIVE.fetch_sub(layout.size(), Relaxed);
            allocated(size);
        }
        replacement
    }
}

#[global_allocator]
static ALLOCATOR: Meter = Meter;

fn peak(operation: impl FnOnce()) -> usize {
    let baseline = LIVE.load(Relaxed);
    PEAK.store(baseline, Relaxed);
    operation();
    PEAK.load(Relaxed).saturating_sub(baseline)
}

fn calibrate() {
    const MIB: usize = 1024 * 1024;
    let baseline = LIVE.load(Relaxed);
    let maximum = peak(|| {
        let reserve = Vec::<u8>::with_capacity(MIB);
        std::hint::black_box(&reserve);
        assert!(LIVE.load(Relaxed) >= baseline + MIB);
        drop(reserve);
        let mut memory = vec![0u8; MIB];

        std::hint::black_box(&memory);
        assert!(LIVE.load(Relaxed) >= baseline + MIB);
        memory.resize(2 * MIB, 42);
        std::hint::black_box(&memory);
        assert!(LIVE.load(Relaxed) >= baseline + 2 * MIB);
        memory.truncate(MIB / 2);
        memory.shrink_to_fit();
        std::hint::black_box(&memory);
        assert!(LIVE.load(Relaxed) < baseline + MIB);
    });
    assert!(maximum >= 2 * MIB, "peak meter missed allocated memory");
    assert!(
        LIVE.load(Relaxed) <= baseline + 4096,
        "freed memory stayed charged"
    );
}

/// spec: G23, M16, E4, E20
#[test]
fn resync_inventory_peak_follows_dependencies_and_not_unrelated_host_state() {
    calibrate();
    for (vrf, related) in [(false, false), (true, false), (true, true)] {
        for failed in [false, true] {
            let mut smallest = None;
            let mut smallest_initial = None;
            for count in [1, 100, 10_000usize] {
                let mut kernel = FakeKernel::new(42);
                let parent = kernel.add_link("parent", vrf);
                let member = kernel.add_link("member", false);
                kernel.set_master(member, Some(parent));
                kernel.add_addr(member, "192.0.2.1".parse().unwrap());
                for n in 0..count {
                    let sibling = kernel.add_link(&format!("noise{n}"), false);
                    kernel.set_master(sibling, Some(parent));
                    kernel.add_addr(sibling, [198, 19, (n >> 8) as u8, n as u8].into());
                }
                kernel.take_monitor();
                let wanted = if related { "parent" } else { "member" };
                let config = toml::from_str(&format!(
                    "[host]\nfix_bindv6only=false\n[tunnels.a]\ntunnel_id=10\nremote_addr='192.0.2.2'\nbind_interface='{wanted}'\n"
                )).unwrap();
                let mut r = Reconciler::new(kernel, Box::<IphostResolve>::default());
                let initial = peak(|| assert!(r.reconcile(config)));
                let initial_baseline = *smallest_initial.get_or_insert(initial);
                let allowance = 16 * 1024 + if related { count * 4096 } else { 0 };
                assert!(
                    initial <= initial_baseline + allowance,
                    "initial inventory peak vrf={vrf} related={related} count={count}: {initial} versus {initial_baseline}"
                );
                println!(
                    "INITIAL_INVENTORY_PEAK vrf={vrf} related={related} count={count} extra_bytes={initial}"
                );
                let socket = r.kernel().tunnel_socket(10).unwrap();
                let original = r.kernel().connection(socket);
                assert!(original.is_some());
                assert_eq!(r.next_deadline(), None);
                if failed {
                    // Refuse completion of the second scan, after visiting its records.
                    r.kernel_mut()
                        .fail_after("dump-end", 1, nix::errno::Errno::EIO);
                }
                let maximum = peak(|| r.handle(Source::Monitor, Notice::Loss));
                let baseline = *smallest.get_or_insert(maximum);
                assert!(
                    maximum <= baseline + allowance,
                    "inventory peak vrf={vrf} related={related} failed={failed} count={count}: {maximum} versus {baseline}"
                );
                if failed {
                    assert!(
                        r.next_deadline().is_some(),
                        "failed scan did not arm recovery"
                    );
                    r.kernel_mut().advance(Duration::from_secs(1));
                    r.tick();
                }
                assert_eq!(r.next_deadline(), None);
                assert!(r.ready());
                assert_eq!(r.kernel().tunnel_socket(10), Some(socket));
                assert_eq!(r.kernel().connection(socket), original);
                println!(
                    "INVENTORY_PEAK vrf={vrf} related={related} failed={failed} count={count} extra_bytes={maximum}"
                );
            }
        }
    }
}
