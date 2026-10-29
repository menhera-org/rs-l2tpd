//! L2TP generic netlink through the bounded request adapter, with the
//! codecs of `netlink-packet-generic` and `netlink-packet-l2tp` (spec
//! K16–K20, K35), and the `l2tp` group subscription (K41).
//!
//! `l2tp::L2tpHandle::events_bounded` is not used for the subscription:
//! creating an `L2tpHandle` needs a Tokio runtime and spawns a
//! `netlink-proto` connection, and `BoundedEvents` registers its socket at
//! creation, while a `Subscription` is created on the reconciler's thread
//! and polled on the service runtime. The raw socket below is the same
//! design: read straight from the kernel, bounded by its buffer.

use std::io;
use std::os::fd::RawFd;
use std::time::Instant;

use l2tp::KernelMessage;
use netlink_packet_core::ParseableParametrized;
use netlink_packet_generic::constants::GENL_HDRLEN;
use netlink_packet_generic::ctrl::nlas::{GenlCtrlAttrs, McastGrpAttrs};
use netlink_packet_generic::ctrl::{GenlCtrl, GenlCtrlCmd};
use netlink_packet_generic::{GenlHeader, GenlMessage};
use netlink_packet_l2tp::{L2tpAttribute, L2tpCmd, L2tpEncapType, L2tpMessage, L2tpPwType};
use netlink_sys::protocols::NETLINK_GENERIC;
use nix::libc;

use super::monitor::Feed;
use super::request::{DEADLINE, Msg, Request, errno, subscribe};
use crate::kernel::{L2tpIfName, Notice, ReportedCookie, SessionCreate, SessionInfo, TunnelInfo};

/// The family's name and the name of its multicast group.
const FAMILY: &str = "l2tp";

/// `L2TP_L2SPECTYPE_NONE`: no layer-2-specific sublayer (S3).
const L2SPEC_NONE: u8 = 0;

// kernel: net/netlink/genetlink.c genl_rcv_msg, genlmsg_put (K1)
/// The L2TP message of a reply or a notification. `l2tp::KernelMessage`
/// accepts the cookie lengths the kernel reports (K35), which
/// `netlink-packet-l2tp` alone refuses.
fn decode(payload: &[u8]) -> io::Result<L2tpMessage> {
    let proto = |_| errno(libc::EPROTO);
    let header = GenlHeader::parse(payload).map_err(proto)?;
    KernelMessage::parse_with_param(payload.get(GENL_HDRLEN..).unwrap_or_default(), header)
        .map(|m| m.0)
        .map_err(proto)
}

// kernel: (K35) net/l2tp/l2tp_netlink.c:584-600, 733-736: any length up to 8,
// put only when not empty
fn cookie(bytes: &[u8]) -> io::Result<ReportedCookie> {
    ReportedCookie::new(bytes).map_err(|_| errno(libc::EPROTO))
}

// kernel: (K16, K35) net/l2tp/l2tp_netlink.c l2tp_nl_session_send (731-732: the
// stored creation name, l2tp_eth.c:310)
fn session_info(message: &L2tpMessage) -> io::Result<SessionInfo> {
    let (mut tunnel, mut session, mut peer) = (None, None, None);
    let mut info = SessionInfo {
        tunnel_id: 0,
        session_id: 0,
        peer_session_id: 0,
        cookie: ReportedCookie::default(),
        peer_cookie: ReportedCookie::default(),
        ifname: None,
    };
    for attr in &message.attributes {
        match attr {
            L2tpAttribute::ConnId(v) => tunnel = Some(*v),
            L2tpAttribute::SessionId(v) => session = Some(*v),
            L2tpAttribute::PeerSessionId(v) => peer = Some(*v),
            L2tpAttribute::Cookie(v) => info.cookie = cookie(v)?,
            L2tpAttribute::PeerCookie(v) => info.peer_cookie = cookie(v)?,
            L2tpAttribute::IfName(name) => info.ifname = Some(*name),
            _ => {}
        }
    }
    let missing = || errno(libc::EPROTO);
    info.tunnel_id = tunnel.ok_or_else(missing)?;
    info.session_id = session.ok_or_else(missing)?;
    info.peer_session_id = peer.ok_or_else(missing)?;
    Ok(info)
}

// kernel: (K16) net/l2tp/l2tp_netlink.c l2tp_nl_cmd_tunnel_get (472) and
// l2tp_nl_session_get (55-57): ENODEV when absent
/// `None` for `ENODEV`.
fn absent<T>(result: io::Result<Option<T>>) -> io::Result<Option<T>> {
    match result {
        Err(error) if error.raw_os_error() == Some(libc::ENODEV) => Ok(None),
        other => other,
    }
}

// kernel: (K41) net/l2tp/l2tp_netlink.c:102-160 l2tp_tunnel_notify and
// l2tp_session_notify, sent before the deletion starts
/// A deletion announced on the `l2tp` group; other commands are ignored,
/// and an announcement that cannot be read is a loss.
fn notice(family: u16, msg: &Msg<'_>) -> Option<Notice> {
    if msg.kind != family {
        return None;
    }
    let Ok(message) = decode(msg.payload) else {
        return Some(Notice::Loss);
    };
    let attr = |want: fn(&L2tpAttribute) -> Option<u32>| message.attributes.iter().find_map(want);
    let tunnel = attr(|a| match a {
        L2tpAttribute::ConnId(v) => Some(*v),
        _ => None,
    });
    let session = attr(|a| match a {
        L2tpAttribute::SessionId(v) => Some(*v),
        _ => None,
    });
    let notice = match message.cmd {
        L2tpCmd::TunnelDelete => tunnel.map(|tunnel_id| Notice::TunnelDeleted { tunnel_id }),
        L2tpCmd::SessionDelete => {
            tunnel
                .zip(session)
                .map(|(tunnel_id, session_id)| Notice::SessionDeleted {
                    tunnel_id,
                    session_id,
                })
        }
        _ => return None,
    };
    Some(notice.unwrap_or(Notice::Loss))
}

/// The generic-netlink request socket and the resolved family.
pub(super) struct Genl {
    request: Request,
    /// The family's identifier and its `l2tp` group.
    family: Option<(u16, Option<u32>)>,
}

impl Genl {
    // kernel: (K1, K21) net/netlink/genetlink.c:1446-1447,
    // net/l2tp/l2tp_netlink.c:620-626 (the request autoloads l2tp_netlink)
    /// Opens the socket and resolves the family at once (L9).
    pub(super) fn new() -> io::Result<Self> {
        let mut genl = Genl {
            request: Request::new(NETLINK_GENERIC)?,
            family: None,
        };
        genl.family(Instant::now() + DEADLINE)?;
        Ok(genl)
    }

    // kernel: (K1, K21, K41) net/netlink/genetlink.c ctrl_getfamily,
    // ctrl_fill_info (CTRL_ATTR_FAMILY_ID, CTRL_ATTR_MCAST_GROUPS);
    // include/uapi/linux/l2tp.h:201 (L2TP_GENL_MCGROUP "l2tp")
    fn family(&mut self, deadline: Instant) -> io::Result<(u16, Option<u32>)> {
        if let Some(family) = self.family {
            return Ok(family);
        }
        let request = GenlMessage::from_payload(GenlCtrl {
            cmd: GenlCtrlCmd::GetFamily,
            nlas: vec![GenlCtrlAttrs::FamilyName(FAMILY.into())],
        });
        let mut found = None;
        self.request
            .run(request, false, deadline, &mut |_, payload| {
                let proto = |_| errno(libc::EPROTO);
                let header = GenlHeader::parse(payload).map_err(proto)?;
                let ctrl = GenlCtrl::parse_with_param(
                    payload.get(GENL_HDRLEN..).unwrap_or_default(),
                    header,
                )
                .map_err(proto)?;
                let (mut id, mut group) = (None, None);
                for nla in ctrl.nlas {
                    match nla {
                        GenlCtrlAttrs::FamilyId(v) => id = Some(v),
                        GenlCtrlAttrs::McastGroups(groups) => {
                            group = groups
                                .iter()
                                .filter(|g| g.contains(&McastGrpAttrs::Name(FAMILY.into())))
                                .flatten()
                                .find_map(|a| match a {
                                    McastGrpAttrs::Id(id) => Some(*id),
                                    _ => None,
                                });
                        }
                        _ => {}
                    }
                }
                found = Some((id.ok_or_else(|| errno(libc::EPROTO))?, group));
                Ok(())
            })?;
        let family = found.ok_or_else(|| errno(libc::EPROTO))?;
        self.family = Some(family);
        Ok(family)
    }

    // kernel: (K1) net/netlink/genetlink.c genl_rcv_msg (ENOENT for a family
    // the kernel no longer has, as after l2tp_netlink is reloaded)
    /// One request of the family within `deadline`, family resolution
    /// included (A14).
    fn run(
        &mut self,
        message: L2tpMessage,
        dump: bool,
        deadline: Instant,
        visit: &mut dyn FnMut(&L2tpMessage) -> io::Result<()>,
    ) -> io::Result<()> {
        let (id, _) = self.family(deadline)?;
        let mut genl = GenlMessage::from_payload(message);
        genl.set_resolved_family_id(id);
        let result = self.request.run(genl, dump, deadline, &mut |_, payload| {
            visit(&decode(payload)?)
        });
        if result.as_ref().err().and_then(io::Error::raw_os_error) == Some(libc::ENOENT) {
            self.family = None;
        }
        result
    }

    // kernel: net/l2tp/l2tp_netlink.c:31-34 (an ACK and nothing else) (K1)
    fn command(&mut self, cmd: L2tpCmd, attributes: Vec<L2tpAttribute>) -> io::Result<()> {
        let deadline = Instant::now() + DEADLINE;
        self.run(
            L2tpMessage { cmd, attributes },
            false,
            deadline,
            &mut |_| Ok(()),
        )
    }

    // kernel: (K2, K4, K5, K19) net/l2tp/l2tp_netlink.c
    // l2tp_nl_cmd_tunnel_create (the socket from L2TP_ATTR_FD, addresses
    // ignored); l2tp_core.c:1467-1503: no socket state check, EEXIST for a
    // taken identifier
    pub(super) fn register_tunnel(
        &mut self,
        fd: RawFd,
        tunnel_id: u32,
        peer: u32,
    ) -> io::Result<()> {
        self.command(
            L2tpCmd::TunnelCreate,
            vec![
                L2tpAttribute::ConnId(tunnel_id),
                L2tpAttribute::PeerConnId(peer),
                L2tpAttribute::ProtoVersion(3),
                L2tpAttribute::EncapType(L2tpEncapType::Ip),
                L2tpAttribute::Fd(fd),
            ],
        )
    }

    // kernel: (K25) net/l2tp/l2tp_netlink.c l2tp_nl_cmd_tunnel_get,
    // l2tp_nl_tunnel_send (337, 359: a disconnected AF_INET6 socket shows the
    // previous peer)
    pub(super) fn tunnel(&mut self, tunnel_id: u32) -> io::Result<Option<TunnelInfo>> {
        let mut info = None;
        let message = L2tpMessage {
            cmd: L2tpCmd::TunnelGet,
            attributes: vec![L2tpAttribute::ConnId(tunnel_id)],
        };
        let result = self.run(message, false, Instant::now() + DEADLINE, &mut |reply| {
            let peer = reply.attributes.iter().find_map(|a| match a {
                L2tpAttribute::PeerConnId(v) => Some(*v),
                _ => None,
            });
            info = Some(TunnelInfo {
                tunnel_id,
                peer_tunnel_id: peer.ok_or_else(|| errno(libc::EPROTO))?,
            });
            Ok(())
        });
        absent(result.map(|()| info))
    }

    // kernel: (K3, K15, K19, K20, K35) net/l2tp/l2tp_netlink.c
    // l2tp_nl_cmd_session_create (521-600: L2SPEC_TYPE defaults to DEFAULT when
    // absent, cookies of up to 8 bytes), l2tp_eth.c:249-310 (the explicit name,
    // refused when taken, copied once); cookies are the only admission check
    pub(super) fn create_session(
        &mut self,
        create: &SessionCreate,
        deadline: Instant,
    ) -> io::Result<()> {
        let mut attributes = vec![
            L2tpAttribute::ConnId(create.tunnel_id),
            L2tpAttribute::SessionId(create.session_id),
            L2tpAttribute::PeerSessionId(create.peer_session_id),
            L2tpAttribute::PwType(L2tpPwType::Eth),
            L2tpAttribute::L2SpecType(L2SPEC_NONE),
            L2tpAttribute::IfName(create.ifname),
        ];
        if let Some(cookie) = create.cookie {
            attributes.push(L2tpAttribute::Cookie(cookie.as_bytes().to_vec()));
        }
        if let Some(cookie) = create.peer_cookie {
            attributes.push(L2tpAttribute::PeerCookie(cookie.as_bytes().to_vec()));
        }
        let message = L2tpMessage {
            cmd: L2tpCmd::SessionCreate,
            attributes,
        };
        self.run(message, false, deadline, &mut |_| Ok(()))
    }

    // kernel: (K16, K19) net/l2tp/l2tp_netlink.c l2tp_nl_cmd_session_get;
    // v6.12 l2tp_core.c:315-321 selects the namespace-wide v3 IP lookup
    pub(super) fn session(
        &mut self,
        tunnel_id: u32,
        session_id: u32,
    ) -> io::Result<Option<SessionInfo>> {
        self.session_until(tunnel_id, session_id, Instant::now() + DEADLINE)
    }

    // kernel: (K19) v6.12 net/l2tp/l2tp_core.c:315-321; a reply's tunnel
    // must match even when the kernel's IP lookup ignored the requested ID
    fn session_until(
        &mut self,
        tunnel_id: u32,
        session_id: u32,
        deadline: Instant,
    ) -> io::Result<Option<SessionInfo>> {
        let mut info = None;
        let message = L2tpMessage {
            cmd: L2tpCmd::SessionGet,
            attributes: vec![
                L2tpAttribute::ConnId(tunnel_id),
                L2tpAttribute::SessionId(session_id),
            ],
        };
        let result = self.run(message, false, deadline, &mut |reply| {
            let session = session_info(reply)?;
            if (session.tunnel_id, session.session_id) == (tunnel_id, session_id) {
                info = Some(session);
            }
            Ok(())
        });
        absent(result.map(|()| info))
    }

    // kernel: (K16, K19) net/l2tp/l2tp_netlink.c l2tp_nl_cmd_session_dump
    // (829-872: every tunnel of the namespace, attributes ignored; by position
    // before 6.12)
    /// The dump, streamed; the tunnel filter is applied here.
    pub(super) fn scan_sessions(
        &mut self,
        tunnel_id: Option<u32>,
        visit: &mut dyn FnMut(&SessionInfo),
    ) -> io::Result<()> {
        let message = L2tpMessage::new(L2tpCmd::SessionGet);
        self.run(message, true, Instant::now() + DEADLINE, &mut |reply| {
            let info = session_info(reply)?;
            if tunnel_id.is_none_or(|t| t == info.tunnel_id) {
                visit(&info);
            }
            Ok(())
        })
    }

    // kernel: (K18) net/l2tp/l2tp_netlink.c l2tp_nl_cmd_session_delete
    // (652-660); synchronous through 6.11, a workqueue from 6.12
    pub(super) fn delete_session(&mut self, tunnel_id: u32, session_id: u32) -> io::Result<()> {
        let deadline = Instant::now() + DEADLINE;
        if self
            .session_until(tunnel_id, session_id, deadline)?
            .is_none()
        {
            return Err(errno(libc::ENODEV));
        }
        self.run(
            L2tpMessage {
                cmd: L2tpCmd::SessionDelete,
                attributes: vec![
                    L2tpAttribute::ConnId(tunnel_id),
                    L2tpAttribute::SessionId(session_id),
                ],
            },
            false,
            deadline,
            &mut |_| Ok(()),
        )
    }

    // kernel: (K16, K18) net/l2tp/l2tp_netlink.c:55-57 (L2TP_ATTR_IFNAME takes
    // precedence, namespace-wide), l2tp_core.c:317-340
    pub(super) fn delete_session_by_name(&mut self, ifname: &L2tpIfName) -> io::Result<()> {
        self.command(L2tpCmd::SessionDelete, vec![L2tpAttribute::IfName(*ifname)])
    }

    // kernel: (K29, K41) net/l2tp/l2tp_netlink.c:664-665 (the group), 102-160;
    // joining needs no capability
    /// The `l2tp` group subscription (E27).
    pub(super) fn events(&mut self) -> io::Result<Feed> {
        let (family, group) = self.family(Instant::now() + DEADLINE)?;
        let group = group.ok_or_else(|| errno(libc::ENOENT))?;
        Ok(Feed::new(
            subscribe(NETLINK_GENERIC, &[group])?,
            Box::new(move |msg| notice(family, msg)),
            Box::new(move || subscribe(NETLINK_GENERIC, &[group])),
        ))
    }
}

#[cfg(test)]
mod tests {
    use netlink_packet_core::Emitable;

    use super::*;

    // kernel: net/l2tp/l2tp_netlink.c:584-600,913-920 (K35)
    /// spec: K35, S28, O5, S16
    #[test]
    #[ignore = "isolated network namespace with CAP_NET_ADMIN and L2TP modules"]
    fn every_foreign_cookie_length_is_read_without_relaxing_configuration() {
        use netlink_packet_core::{Emitable, NetlinkSerializable, Nla};
        use std::os::fd::AsRawFd;
        #[derive(Debug)]
        struct Foreign(u16, Vec<u8>);
        impl NetlinkSerializable for Foreign {
            // kernel: include/uapi/linux/netlink.h nlmsg_type (K35)
            fn message_type(&self) -> u16 {
                self.0
            }
            // kernel: include/uapi/linux/netlink.h nlmsg_len (K35)
            fn buffer_len(&self) -> usize {
                self.1.len()
            }
            // kernel: net/l2tp/l2tp_netlink.c cookie length policy (K35)
            fn serialize(&self, buffer: &mut [u8]) {
                buffer.copy_from_slice(&self.1);
            }
        }
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
        let tunnel =
            super::super::socket::Tunnel::create(crate::kernel::Family::V6, 9361, 9362).unwrap();
        let mut genl = Genl::new().unwrap();
        genl.register_tunnel(tunnel.socket.as_raw_fd(), 9361, 9362)
            .unwrap();
        for len in 0..=8 {
            let name = crate::kernel::L2tpIfName::new(format!("foreign-{len}").as_bytes()).unwrap();
            let message = L2tpMessage {
                cmd: L2tpCmd::SessionCreate,
                attributes: vec![
                    L2tpAttribute::ConnId(9361),
                    L2tpAttribute::SessionId(93610 + len),
                    L2tpAttribute::PeerSessionId(93610 + len),
                    L2tpAttribute::PwType(L2tpPwType::Eth),
                    L2tpAttribute::L2SpecType(L2SPEC_NONE),
                    L2tpAttribute::IfName(name),
                ],
            };
            let mut body = vec![0; message.buffer_len()];
            message.emit(&mut body);
            // Fixture-only foreign input: the daemon never emits odd cookies.
            for (kind, byte) in [
                (L2tpAttribute::Cookie(Vec::new()).kind(), 0x5a),
                (L2tpAttribute::PeerCookie(Vec::new()).kind(), 0xa5),
            ] {
                let size = 4 + len as usize;
                body.extend((size as u16).to_ne_bytes());
                body.extend(kind.to_ne_bytes());
                body.extend(vec![byte; len as usize]);
                body.resize(body.len().next_multiple_of(4), 0);
            }
            let mut bytes = vec![L2tpCmd::SessionCreate.into(), 1, 0, 0];
            bytes.extend(body);
            let family = genl.family(Instant::now() + DEADLINE).unwrap().0;
            genl.request
                .run(
                    Foreign(family, bytes),
                    false,
                    Instant::now() + DEADLINE,
                    &mut |_, _| Ok(()),
                )
                .unwrap();
            let session = genl.session(9361, 93610 + len).unwrap().unwrap();
            assert_eq!(session.cookies().is_ok(), matches!(len, 0 | 4 | 8));
            let debug = format!("{session:?}");
            assert!(!debug.contains("90, 90") && !debug.contains("165, 165"));
            genl.delete_session(9361, 93610 + len).unwrap();
        }
    }

    // kernel: net/netlink/genetlink.c genlmsg_put (K41)
    fn payload(cmd: L2tpCmd, attributes: Vec<L2tpAttribute>) -> Vec<u8> {
        let genl = GenlMessage::from_payload(L2tpMessage { cmd, attributes });
        let mut out = vec![0; genl.buffer_len()];
        genl.emit(&mut out);
        out
    }

    // kernel: net/l2tp/l2tp_netlink.c:102-160 (K41)
    /// spec: K41, E27, E21
    #[test]
    fn deletions_decode_into_notices() {
        let ids = vec![L2tpAttribute::ConnId(5), L2tpAttribute::SessionId(9)];
        let session = payload(L2tpCmd::SessionDelete, ids.clone());
        let msg = |kind, payload| Msg {
            kind,
            flags: 0,
            seq: 0,
            payload,
        };
        assert_eq!(
            notice(30, &msg(30, &session)),
            Some(Notice::SessionDeleted {
                tunnel_id: 5,
                session_id: 9
            })
        );
        let tunnel = payload(L2tpCmd::TunnelDelete, ids.clone());
        assert_eq!(
            notice(30, &msg(30, &tunnel)),
            Some(Notice::TunnelDeleted { tunnel_id: 5 })
        );
        assert_eq!(notice(31, &msg(30, &session)), None);
        let created = payload(L2tpCmd::SessionCreate, ids);
        assert_eq!(notice(30, &msg(30, &created)), None);
        let bare = payload(L2tpCmd::SessionDelete, vec![]);
        assert_eq!(notice(30, &msg(30, &bare)), Some(Notice::Loss));
    }

    // kernel: net/l2tp/l2tp_netlink.c l2tp_nl_session_send (K16, K35)
    /// spec: K16, K35, S22, O5
    #[test]
    fn a_session_record_decodes_names_and_cookies() {
        let name = L2tpIfName::new(b"rsl2tp-t0a0b0c").unwrap();
        let reply = L2tpMessage {
            cmd: L2tpCmd::SessionGet,
            attributes: vec![
                L2tpAttribute::ConnId(1),
                L2tpAttribute::SessionId(2),
                L2tpAttribute::PeerSessionId(3),
                L2tpAttribute::Cookie(vec![1, 2, 3, 4]),
                L2tpAttribute::IfName(name),
            ],
        };
        let info = session_info(&reply).unwrap();
        assert_eq!(
            (info.tunnel_id, info.session_id, info.peer_session_id),
            (1, 2, 3)
        );
        let (cookie, peer_cookie) = info.cookies().unwrap();
        assert_eq!(
            cookie.map(|c| c.as_bytes().to_vec()),
            Some(vec![1, 2, 3, 4])
        );
        assert_eq!((peer_cookie, info.ifname), (None, Some(name)));
        // A foreign 2-byte cookie, which the codec refuses to emit, is made
        // by shortening the cookie attribute's length in the bytes
        // (L2TP_ATTR_COOKIE is 15). It decodes (K35) but matches no
        // configuration (C8), and is never printed (O5).
        let genl = GenlMessage::from_payload(reply);
        let mut out = vec![0; genl.buffer_len()];
        genl.emit(&mut out);
        let at = out.windows(4).position(|w| w == [8, 0, 15, 0]).unwrap();
        out[at] = 6;
        let foreign = session_info(&decode(&out).unwrap()).unwrap();
        assert_eq!(foreign.cookie.0.as_bytes(), [1, 2]);
        assert!(foreign.cookies().is_err());
        assert!(!format!("{foreign:?}").contains("[1, 2]"));
    }
}
