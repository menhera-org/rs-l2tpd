//! The classic BPF program of the event monitor (spec A5, K10): it passes
//! `RTM_NEWLINK` and `RTM_DELLINK` of family `AF_UNSPEC` (E5) and
//! `RTM_NEWADDR` and `RTM_DELADDR`, and drops every other message.

use nix::libc;
use socket2::SockFilter;

// include/uapi/linux/bpf_common.h: BPF_LD|BPF_H|BPF_ABS, BPF_LD|BPF_B|BPF_ABS,
// BPF_JMP|BPF_JEQ|BPF_K, BPF_RET|BPF_K.
const LD_H_ABS: u16 = 0x28;
const LD_B_ABS: u16 = 0x30;
const JEQ_K: u16 = 0x15;
const RET_K: u16 = 0x06;

/// `nlmsg_type`, after the 32-bit length.
const TYPE: u32 = 4;
/// `ifi_family` and `ifa_family`, after the 16-byte netlink header.
const FAMILY: u32 = 16;

// kernel: (K10) net/core/filter.c bpf_skb_load_helper_16 loads big-endian,
// while the netlink header is in host order
/// The constant a half-word load of `value`'s host-order bytes yields.
const fn loaded(value: u16) -> u32 {
    u16::from_be_bytes(value.to_ne_bytes()) as u32
}

/// The program: (code, jump if true, jump if false, constant).
pub(super) const PROGRAM: [(u16, u8, u8, u32); 9] = [
    (LD_H_ABS, 0, 0, TYPE),
    (JEQ_K, 3, 0, loaded(libc::RTM_NEWLINK)), // -> 5
    (JEQ_K, 2, 0, loaded(libc::RTM_DELLINK)), // -> 5
    (JEQ_K, 4, 0, loaded(libc::RTM_NEWADDR)), // -> 8
    (JEQ_K, 3, 2, loaded(libc::RTM_DELADDR)), // -> 8, else 7
    (LD_B_ABS, 0, 0, FAMILY),
    (JEQ_K, 1, 0, libc::AF_UNSPEC as u32), // -> 8, else 7
    (RET_K, 0, 0, 0),
    (RET_K, 0, 0, u32::MAX),
];

// kernel: net/core/filter.c sk_attach_filter, bpf_check_classic (K10)
/// The program in the form `SO_ATTACH_FILTER` takes.
pub(super) fn filter() -> Vec<SockFilter> {
    PROGRAM
        .iter()
        .map(|&(code, jt, jf, k)| SockFilter::new(code, jt, jf, k))
        .collect()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    // kernel: (K10) net/core/filter.c the classic interpreter's LD_ABS, JEQ and
    // RET
    /// Runs `PROGRAM` on a packet as the kernel's interpreter would.
    fn accepts(packet: &[u8]) -> bool {
        let (mut pc, mut a) = (0, 0u32);
        loop {
            let (code, jt, jf, k) = PROGRAM[pc];
            let at = k as usize;
            pc += 1;
            match code {
                LD_H_ABS => a = u16::from_be_bytes([packet[at], packet[at + 1]]).into(),
                LD_B_ABS => a = packet[at].into(),
                JEQ_K => pc += usize::from(if a == k { jt } else { jf }),
                RET_K => return k != 0,
                _ => unreachable!(),
            }
        }
    }

    // kernel: include/uapi/linux/netlink.h struct nlmsghdr (K10)
    fn message(kind: u16, family: u8) -> Vec<u8> {
        let mut out = 32u32.to_ne_bytes().to_vec();
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(&[0; 10]);
        out.push(family);
        out.resize(32, 0);
        out
    }

    // kernel: (K10) net/core/rtnetlink.c rtmsg_ifinfo (AF_UNSPEC), net/bridge
    // br_ifinfo_notify (AF_BRIDGE)
    /// spec: A5, E5, K10
    #[test]
    fn the_filter_passes_lifetimes_and_addresses_only() {
        let bridge = libc::AF_BRIDGE as u8;
        let inet6 = libc::AF_INET6 as u8;
        assert!(accepts(&message(libc::RTM_NEWLINK, 0)));
        assert!(accepts(&message(libc::RTM_DELLINK, 0)));
        assert!(!accepts(&message(libc::RTM_NEWLINK, bridge)));
        assert!(!accepts(&message(libc::RTM_DELLINK, inet6)));
        assert!(accepts(&message(libc::RTM_NEWADDR, inet6)));
        assert!(accepts(&message(libc::RTM_DELADDR, 2)));
        assert!(!accepts(&message(libc::RTM_NEWROUTE, 0)));
        assert!(!accepts(&message(libc::RTM_NEWNEIGH, 0)));
        assert_eq!(filter().len(), PROGRAM.len());
    }
}
