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
        self.0.net_raw()
    }
    fn send_frame(&mut self, index: u32) {
        self.0.send_frame(index);
    }
    fn tx_drops(&mut self, index: u32) -> u64 {
        self.0.tx_drops(index)
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

/// spec: K16, K17, K18, K19, K20, K22, K24, K26, K27, K28, K31, K34, K35, K37, K41, S9, S19, S28, E5, T7, O5
#[test]
fn conformance_on_the_fake_kernel() {
    for (net_raw, asynchronous) in [(false, false), (false, true), (true, false), (true, true)] {
        for (case, run) in conformance::CASES {
            let mut kernel = FakeKernel::new(7);
            kernel.set_net_raw(net_raw);
            kernel.set_async_session_delete(asynchronous);
            eprintln!(
                "case {case}: inet6={} bindv6only={} only_v6_error={:?} net_raw={} async_delete={} tunnel_delete_delay={:?}",
                kernel.inet6(),
                kernel.bindv6only(),
                kernel.only_v6_error(),
                kernel.net_raw(),
                kernel.async_session_delete(),
                kernel.tunnel_delete_delay(),
            );
            run(&mut FakeFixture(kernel));
        }
    }
}
