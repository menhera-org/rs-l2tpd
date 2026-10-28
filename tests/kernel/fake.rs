//! The conformance suite against the fake kernel (docs/testing.md); the
//! same cases run against the real kernel in `linux.rs`.

#[path = "conformance.rs"]
mod conformance;

use std::net::IpAddr;
use std::task::{Context, Poll, Waker};

use conformance::Fixture;
use rs_l2tpd::kernel::fake::FakeKernel;
use rs_l2tpd::kernel::{Kernel, Notice, Subscription};

struct FakeFixture(FakeKernel);

impl Fixture for FakeFixture {
    fn k(&mut self) -> &mut dyn Kernel {
        &mut self.0
    }
    fn add_link(&mut self, name: &str, vrf: bool) -> u32 {
        self.0.add_link(name, vrf)
    }
    fn set_up(&mut self, index: u32, up: bool) {
        self.0.set_up(index, up)
    }
    fn set_master(&mut self, index: u32, master: u32) {
        self.0.set_master(index, Some(master))
    }
    fn add_addr(&mut self, index: u32, addr: IpAddr) {
        self.0.add_addr(index, addr)
    }
    fn rename_link(&mut self, index: u32, name: &str) {
        self.0.rename_link(index, name)
    }
    fn settle(&mut self) {
        self.0.tick()
    }
    fn net_raw(&self) -> bool {
        self.0.net_raw
    }
    fn wait_notice(
        &mut self,
        sub: &mut dyn Subscription,
        want: &mut dyn FnMut(&Notice) -> bool,
    ) -> Option<Notice> {
        let mut cx = Context::from_waker(Waker::noop());
        while let Poll::Ready(notice) = sub.poll_notice(&mut cx) {
            if want(&notice) {
                return Some(notice);
            }
        }
        None
    }
}

/// spec: K16, K17, K18, K19, K20, K22, K24, K26, K27, K28, K31, K34, K41, S9, S19, E5, T7
#[test]
fn conformance_on_the_fake_kernel() {
    for (case, run) in conformance::CASES {
        eprintln!("case {case}");
        run(&mut FakeFixture(FakeKernel::new(7)));
    }
}
