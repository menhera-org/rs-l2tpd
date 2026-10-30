//! rtnetlink requests on a socket of their own: links by name, renames,
//! hardware addresses, dumps (spec A5, K32), and the decoding of link and
//! address messages the subscriptions share.
//!
//! Replies are decoded here rather than by `netlink-packet-route`, which
//! refuses a whole message whose `IFLA_IFNAME` is not UTF-8: names are
//! bytes (A22), and a foreign device must not break a dump.

use std::io;
use std::net::IpAddr;
use std::time::Instant;

use netlink_packet_core::{DefaultNla, NlasIterator};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_packet_route::address::AddressMessage;
use netlink_packet_route::link::{LinkAttribute, LinkMessage};
use netlink_sys::protocols::NETLINK_ROUTE;
use nix::libc;

use super::request::{DEADLINE, Request, errno};
use crate::kernel::{AddrInfo, HwAddr, L2tpIfName, LinkInfo};

/// A link message, as far as the daemon reads it.
pub(super) struct Link {
    /// `ifi_family`: `AF_UNSPEC` for a device's lifetime (E5).
    pub family: u8,
    /// `ifi_type`, an `ARPHRD_*`.
    pub arphrd: u16,
    pub info: LinkInfo,
    /// `IFLA_ADDRESS` when it has six bytes.
    pub address: Option<[u8; 6]>,
}

// kernel: (K9, K32) net/core/rtnetlink.c rtnl_fill_ifinfo (ifinfomsg,
// IFLA_IFNAME, IFLA_MASTER, IFLA_ADDRESS, IFLA_LINKINFO/IFLA_INFO_KIND "vrf",
// drivers/net/vrf.c)
/// Decodes a link message; `None` for one without an index or a name.
pub(super) fn parse_link(payload: &[u8]) -> Option<Link> {
    let header = payload.get(..16)?;
    let index = u32::from_ne_bytes(header[4..8].try_into().ok()?);
    let flags = u32::from_ne_bytes(header[8..12].try_into().ok()?);
    let (mut name, mut master, mut vrf, mut address) = (None, None, false, None);
    for nla in NlasIterator::new(&payload[16..]) {
        let nla = nla.ok()?;
        let value = nla.value();
        match nla.kind() & libc::NLA_TYPE_MASK as u16 {
            libc::IFLA_IFNAME => {
                name = L2tpIfName::new(value.strip_suffix(&[0]).unwrap_or(value)).ok();
            }
            libc::IFLA_MASTER => master = Some(u32::from_ne_bytes(value.try_into().ok()?)),
            libc::IFLA_ADDRESS => address = value.try_into().ok(),
            libc::IFLA_LINKINFO => {
                for info in NlasIterator::new(value) {
                    let info = info.ok()?;
                    if info.kind() == libc::IFLA_INFO_KIND {
                        vrf = info.value().strip_suffix(&[0]).unwrap_or(info.value()) == b"vrf";
                    }
                }
            }
            _ => {}
        }
    }
    (index != 0).then_some(())?;
    Some(Link {
        family: header[0],
        arphrd: u16::from_ne_bytes([header[2], header[3]]),
        info: LinkInfo {
            index,
            name: name?,
            up: flags & libc::IFF_UP as u32 != 0,
            vrf,
            master: master.filter(|&m| m != 0),
        },
        address,
    })
}

// kernel: (K7) net/ipv4/devinet.c inet_fill_ifaddr, net/ipv6/addrconf.c
// inet6_fill_ifaddr (IFA_LOCAL is the local address of a point-to-point IPv4
// address, IFA_ADDRESS otherwise)
/// Decodes an address message.
pub(super) fn parse_addr(payload: &[u8]) -> Option<AddrInfo> {
    let header = payload.get(..8)?;
    let index = u32::from_ne_bytes(header[4..8].try_into().ok()?);
    (index != 0).then_some(())?;
    let (mut address, mut local) = (None, None);
    for nla in NlasIterator::new(&payload[8..]) {
        let nla = nla.ok()?;
        let kind = nla.kind() & libc::NLA_TYPE_MASK as u16;
        if kind != libc::IFA_ADDRESS && kind != libc::IFA_LOCAL {
            continue;
        }
        let addr = match header[0] as i32 {
            libc::AF_INET => IpAddr::from(<[u8; 4]>::try_from(nla.value()).ok()?),
            libc::AF_INET6 => IpAddr::from(<[u8; 16]>::try_from(nla.value()).ok()?),
            _ => return None,
        };
        if kind == libc::IFA_LOCAL {
            local = Some(addr);
        } else {
            address = Some(addr);
        }
    }
    Some(AddrInfo {
        index,
        addr: local.or(address)?,
    })
}

// kernel: net/core/rtnetlink.c rtnl_getlink (IFLA_IFNAME, ENODEV) (K32)
/// `IFLA_IFNAME` as bytes, NUL-terminated.
fn ifname(name: &L2tpIfName) -> LinkAttribute {
    let mut value = name.as_bytes().to_vec();
    value.push(0);
    LinkAttribute::Other(DefaultNla::new(libc::IFLA_IFNAME, value))
}

// kernel: (K7, K29) net/core/rtnetlink.c rtnl_dump_all visits every
// registered address family; inet_fill_ifaddr and inet6_fill_ifaddr use ifaddrmsg.
fn collect_addr(addrs: &mut Vec<AddrInfo>, kind: u16, payload: &[u8]) -> io::Result<()> {
    if kind == libc::RTM_NEWADDR {
        let family = *payload.first().ok_or_else(|| errno(libc::EPROTO))? as i32;
        if !matches!(family, libc::AF_INET | libc::AF_INET6) {
            return Ok(());
        }
        addrs.push(parse_addr(payload).ok_or_else(|| errno(libc::EPROTO))?);
    }
    Ok(())
}

/// The rtnetlink request socket (A5).
pub(super) struct Rtnl(Request);

impl Rtnl {
    // kernel: net/core/rtnetlink.c rtnetlink_net_init (K7)
    pub(super) fn new() -> io::Result<Self> {
        Ok(Rtnl(Request::new(NETLINK_ROUTE)?))
    }

    // kernel: (K32) net/core/rtnetlink.c rtnl_getlink: by index when ifi_index
    // is set, else by IFLA_IFNAME; ENODEV when absent
    /// One link, `None` when the kernel has none.
    fn get(&mut self, message: LinkMessage) -> io::Result<Option<Link>> {
        let mut link = None;
        let result = self.0.run(
            RouteNetlinkMessage::GetLink(message),
            false,
            Instant::now() + DEADLINE,
            &mut |kind, payload| {
                if kind == libc::RTM_NEWLINK {
                    link = Some(parse_link(payload).ok_or_else(|| errno(libc::EPROTO))?);
                }
                Ok(())
            },
        );
        match result {
            Ok(()) => Ok(link),
            Err(error) if error.raw_os_error() == Some(libc::ENODEV) => Ok(None),
            Err(error) => Err(error),
        }
    }

    // kernel: net/core/rtnetlink.c rtnl_getlink, rtnl_dev_get (K9, K32)
    pub(super) fn link_by_name(&mut self, name: &L2tpIfName) -> io::Result<Option<LinkInfo>> {
        let mut message = LinkMessage::default();
        message.attributes.push(ifname(name));
        Ok(self.get(message)?.map(|link| link.info))
    }

    // kernel: (K9, K32) net/core/rtnetlink.c rtnl_getlink: ifi_index lookup.
    pub(super) fn link_by_index(&mut self, index: u32) -> io::Result<Option<LinkInfo>> {
        let mut message = LinkMessage::default();
        message.header.index = index;
        Ok(self.get(message)?.map(|link| link.info))
    }

    // kernel: (K31) net/core/rtnetlink.c rtnl_getlink; IFLA_ADDRESS of an
    // ARPHRD_ETHER device
    pub(super) fn ether_addr(&mut self, index: u32) -> io::Result<Option<HwAddr>> {
        let mut message = LinkMessage::default();
        message.header.index = index;
        let link = self.get(message)?.ok_or_else(|| errno(libc::ENODEV))?;
        Ok(link
            .address
            .filter(|_| link.arphrd == libc::ARPHRD_ETHER)
            .and_then(|octets| HwAddr::new(octets).ok()))
    }

    // kernel: (K31, K32) net/core/rtnetlink.c rtnl_setlink, do_setlink
    // (IFLA_IFNAME: dev_change_name, EEXIST; IFLA_ADDRESS: dev_set_mac_address,
    // EBUSY from l2tp_eth while up, net/l2tp/l2tp_eth.c:95-115)
    fn set(&mut self, index: u32, attribute: LinkAttribute) -> io::Result<()> {
        let mut message = LinkMessage::default();
        message.header.index = index;
        message.attributes.push(attribute);
        self.0.run(
            RouteNetlinkMessage::SetLink(message),
            false,
            Instant::now() + DEADLINE,
            &mut |_, _| Ok(()),
        )
    }

    // kernel: net/core/dev.c dev_change_name, allowed while up (K31, K32)
    pub(super) fn rename(&mut self, index: u32, name: &L2tpIfName) -> io::Result<()> {
        self.set(index, ifname(name))
    }

    // kernel: net/l2tp/l2tp_eth.c:95-115, net/core/dev.c:1264-1308 (K31)
    pub(super) fn set_hwaddr(&mut self, index: u32, addr: HwAddr) -> io::Result<()> {
        self.set(index, LinkAttribute::Address(addr.octets().to_vec()))
    }

    // kernel: net/core/rtnetlink.c rtnl_dump_ifinfo (K7, K29)
    pub(super) fn dump_links(&mut self) -> io::Result<Vec<LinkInfo>> {
        let mut links = Vec::new();
        self.0.run(
            RouteNetlinkMessage::GetLink(LinkMessage::default()),
            true,
            Instant::now() + DEADLINE,
            &mut |kind, payload| {
                if kind == libc::RTM_NEWLINK {
                    links.push(parse_link(payload).ok_or_else(|| errno(libc::EPROTO))?.info);
                }
                Ok(())
            },
        )?;
        Ok(links)
    }

    // kernel: (K7, K29) net/core/rtnetlink.c rtnl_dump_all over
    // every registered address family
    pub(super) fn dump_addrs(&mut self) -> io::Result<Vec<AddrInfo>> {
        let mut addrs = Vec::new();
        self.0.run(
            RouteNetlinkMessage::GetAddress(AddressMessage::default()),
            true,
            Instant::now() + DEADLINE,
            &mut |kind, payload| collect_addr(&mut addrs, kind, payload),
        )?;
        Ok(addrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // kernel: include/uapi/linux/netlink.h struct nlattr (K29)
    fn nla(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut out = ((4 + value.len()) as u16).to_ne_bytes().to_vec();
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(value);
        out.resize(out.len().next_multiple_of(4), 0);
        out
    }

    // kernel: include/uapi/linux/rtnetlink.h struct ifinfomsg (K9)
    fn link(family: u8, index: u32, flags: u32, attrs: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![family, 0];
        out.extend_from_slice(&libc::ARPHRD_ETHER.to_ne_bytes());
        out.extend_from_slice(&index.to_ne_bytes());
        out.extend_from_slice(&flags.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        attrs.iter().for_each(|a| out.extend_from_slice(a));
        out
    }

    // kernel: net/core/rtnetlink.c rtnl_fill_ifinfo (K9, K32)
    /// spec: A5, K9, E5, A22
    #[test]
    fn a_link_message_decodes_name_bytes_master_and_vrf() {
        let info = nla(libc::IFLA_INFO_KIND, b"vrf\0");
        let payload = link(
            0,
            7,
            libc::IFF_UP as u32,
            &[
                nla(libc::IFLA_IFNAME, b"caf\xc3\0"),
                nla(libc::IFLA_MASTER, &3u32.to_ne_bytes()),
                nla(libc::IFLA_ADDRESS, &[2, 0, 0, 0, 0, 1]),
                nla(libc::IFLA_LINKINFO, &info),
            ],
        );
        let parsed = parse_link(&payload).unwrap();
        assert_eq!(parsed.family, 0);
        assert_eq!(parsed.info.index, 7);
        assert_eq!(parsed.info.name.as_bytes(), b"caf\xc3");
        assert!(parsed.info.up && parsed.info.vrf);
        assert_eq!(parsed.info.master, Some(3));
        assert_eq!(parsed.address, Some([2, 0, 0, 0, 0, 1]));
        let unnamed = link(0, 7, 0, &[]);
        assert!(parse_link(&unnamed).is_none());
    }

    // kernel: (K7, K29) net/core/rtnetlink.c rtnl_fill_ifinfo and net/ipv4/devinet.c inet_fill_ifaddr.
    /// spec: A5, E21
    #[test]
    fn malformed_dump_records_are_not_usable_entries() {
        for payload in [
            vec![],
            link(0, 0, 0, &[nla(libc::IFLA_IFNAME, b"wan\0")]),
            link(
                0,
                1,
                0,
                &[
                    nla(libc::IFLA_IFNAME, b"wan\0"),
                    nla(libc::IFLA_LINKINFO, &[1, 0, 0, 0]),
                ],
            ),
        ] {
            assert!(
                parse_link(&payload)
                    .ok_or_else(|| errno(libc::EPROTO))
                    .is_err()
            );
        }
        let mut payload = vec![libc::AF_INET as u8, 24, 0, 0];
        payload.extend_from_slice(&1u32.to_ne_bytes());
        payload.extend(nla(libc::IFA_LOCAL, &[192, 0, 2]));
        assert!(
            parse_addr(&payload)
                .ok_or_else(|| errno(libc::EPROTO))
                .is_err()
        );
    }

    // kernel: (K7, K29) net/core/rtnetlink.c rtnl_dump_all; net/mctp/device.c
    // mctp_fill_addrinfo; net/phonet/pn_netlink.c fill_addr use one-byte addresses.
    /// spec: A5, E20, E21, K7, K29
    #[test]
    fn address_dump_skips_foreign_families_and_rejects_malformed_inet_records() {
        let addr = |family, value: &[u8]| {
            let mut payload = vec![family, 0, 0, 0];
            payload.extend_from_slice(&7u32.to_ne_bytes());
            payload.extend(nla(libc::IFA_ADDRESS, value));
            payload
        };
        let v4 = addr(libc::AF_INET as u8, &[192, 0, 2, 1]);
        let v6 = addr(libc::AF_INET6 as u8, &[0x20; 16]);
        let mut addrs = Vec::new();
        for payload in [
            v4.clone(),
            addr(45, &[8]), // AF_MCTP (include/linux/socket.h)
            addr(libc::AF_PHONET as u8, &[42]),
            v6.clone(),
        ] {
            collect_addr(&mut addrs, libc::RTM_NEWADDR, &payload).unwrap();
        }
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], parse_addr(&v4).unwrap());
        assert_eq!(addrs[1], parse_addr(&v6).unwrap());
        collect_addr(&mut addrs, libc::RTM_DELADDR, &[]).unwrap();
        assert_eq!(addrs.len(), 2);
        for payload in [
            vec![],
            vec![libc::AF_INET as u8],
            vec![libc::AF_INET6 as u8],
            addr(libc::AF_INET as u8, &[192, 0, 2]),
            addr(libc::AF_INET6 as u8, &[0; 15]),
        ] {
            assert_eq!(
                collect_addr(&mut addrs, libc::RTM_NEWADDR, &payload)
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EPROTO)
            );
            assert_eq!(addrs.len(), 2);
        }
    }

    // kernel: net/ipv4/devinet.c inet_fill_ifaddr (K7)
    /// spec: A5
    #[test]
    fn an_address_message_prefers_the_local_address() {
        let mut payload = vec![2, 24, 0, 0];
        payload.extend_from_slice(&5u32.to_ne_bytes());
        payload.extend(nla(libc::IFA_ADDRESS, &[192, 0, 2, 9]));
        payload.extend(nla(libc::IFA_LOCAL, &[192, 0, 2, 1]));
        let parsed = parse_addr(&payload).unwrap();
        assert_eq!(parsed.index, 5);
        assert_eq!(parsed.addr, "192.0.2.1".parse::<IpAddr>().unwrap());
    }
}
