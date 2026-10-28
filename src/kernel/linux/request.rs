//! The bounded netlink request adapter of generic netlink and rtnetlink,
//! and the socket helpers the subscriptions share (`docs/architecture.md`,
//! "Decisions recorded here"; spec A14, E21, E22, R10).
//!
//! One request is in flight per socket. Its deadline is absolute and
//! covers the send, every reply part and the acknowledgement; a reply is
//! accepted only from port 0 with the request's sequence number. After a
//! failure of the transport the socket is dropped, the next request opens
//! a new one, and the caller gets `ETIMEDOUT`: the outcome is unknown.

use std::fmt::Debug;
use std::io;
use std::os::fd::AsFd;
use std::time::{Duration, Instant};

use netlink_packet_core::{
    DoneBuffer, ErrorBuffer, NLM_F_ACK, NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST, NLMSG_DONE,
    NLMSG_ERROR, NetlinkBuffer, NetlinkHeader, NetlinkMessage, NetlinkPayload, NetlinkSerializable,
};
use netlink_sys::Socket;
use nix::errno::Errno;
use nix::libc;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{setsockopt, sockopt::RcvBufForce};
use socket2::SockRef;

/// The total deadline of one request, family resolution included (A14).
pub(super) const DEADLINE: Duration = Duration::from_secs(5);

/// The receive buffer of a subscription (R10, E20).
const SUBSCRIPTION_BUFFER: usize = 8 << 20;

/// The netlink header's length.
const HEADER: usize = 16;

/// The first type of a protocol's own messages (`NLMSG_MIN_TYPE`).
const NLMSG_MIN_TYPE: u16 = 0x10;

/// One message of a datagram, header fields in host order.
pub(super) struct Msg<'a> {
    pub kind: u16,
    pub flags: u16,
    pub seq: u32,
    pub payload: &'a [u8],
}

/// An error of the given errno.
pub(super) fn errno(code: i32) -> io::Error {
    io::Error::from_raw_os_error(code)
}

// kernel: (K29) net/netlink/af_netlink.c netlink_recvmsg; every message is
// NLMSG_ALIGN-padded (include/uapi/linux/netlink.h)
/// The messages of a received datagram; `EPROTO` when its framing breaks.
pub(super) fn messages(datagram: &[u8]) -> io::Result<Vec<Msg<'_>>> {
    let mut out = Vec::new();
    let mut rest = datagram;
    while !rest.is_empty() {
        let buffer = NetlinkBuffer::new_checked(rest).map_err(|_| errno(libc::EPROTO))?;
        let len = buffer.length() as usize;
        out.push(Msg {
            kind: buffer.message_type(),
            flags: buffer.flags(),
            seq: buffer.sequence_number(),
            payload: &rest[HEADER..len],
        });
        rest = rest.get(len.next_multiple_of(4)..).unwrap_or_default();
    }
    Ok(out)
}

// kernel: (K7, K21) net/netlink/af_netlink.c netlink_bind, netlink_autobind; a
// socket of the kernel's protocols needs no capability to open
/// A non-blocking netlink socket bound to a port the kernel picks.
pub(super) fn open(protocol: isize) -> io::Result<Socket> {
    let mut socket = Socket::new(protocol)?;
    socket.bind_auto()?;
    socket.set_non_blocking(true)?;
    Ok(socket)
}

// kernel: (K7, K29, K36) net/core/sock.c:1080-1083, 1271-1275;
// net/netlink/af_netlink.c netlink_add_membership; NETLINK_NO_ENOBUFS is never
// set, so a loss is seen
/// A subscription socket: 8 MiB of buffer with `SO_RCVBUFFORCE`, else as
/// much as `SO_RCVBUF` gives (R10), joined to `groups`.
pub(super) fn subscribe(protocol: isize, groups: &[u32]) -> io::Result<Socket> {
    let socket = open(protocol)?;
    if setsockopt(&socket, RcvBufForce, &SUBSCRIPTION_BUFFER).is_err()
        && let Err(error) = SockRef::from(&socket).set_recv_buffer_size(SUBSCRIPTION_BUFFER)
    {
        log::warn!("netlink receive buffer: {error}");
    }
    for &group in groups {
        socket.add_membership(group)?;
    }
    Ok(socket)
}

// kernel: net/netlink/af_netlink.c netlink_poll (K29)
/// Waits until `socket` is readable or `deadline` passes (`ETIMEDOUT`).
pub(super) fn wait(socket: &Socket, deadline: Instant) -> io::Result<()> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(errno(libc::ETIMEDOUT));
    }
    // A deadline is at most DEADLINE, which fits; round up so that the
    // wait never ends just before it.
    let ms = u16::try_from(left.as_millis() + 1).unwrap_or(u16::MAX);
    let mut fds = [PollFd::new(socket.as_fd(), PollFlags::POLLIN)];
    match poll(&mut fds, PollTimeout::from(ms)) {
        Ok(_) | Err(Errno::EINTR) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// A request socket of one protocol, opened again after a failure.
pub(super) struct Request {
    protocol: isize,
    socket: Option<Socket>,
    seq: u32,
}

impl Request {
    // kernel: net/netlink/af_netlink.c netlink_autobind (K7)
    /// Opens the socket at once, so that a kernel without the protocol
    /// fails the start (L9).
    pub(super) fn new(protocol: isize) -> io::Result<Self> {
        Ok(Request {
            protocol,
            socket: Some(open(protocol)?),
            seq: 0,
        })
    }

    // kernel: (K29) net/netlink/af_netlink.c netlink_rcv_skb (an ACK on request
    // or error, none after a dump), netlink_dump_done (the dump's errno and
    // NLM_F_DUMP_INTR), __netlink_dump_start (EBUSY while a dump runs)
    /// Sends `payload` and hands the type and payload of every reply to
    /// `visit`, until the acknowledgement, the kernel's error or the end of
    /// the dump. The kernel's error is returned as its errno, and so is the
    /// first error of `visit`, after the replies are drained. Any failure of
    /// the transport within `deadline` drops the socket and returns
    /// `ETIMEDOUT` (A14, E21).
    pub(super) fn run<I: NetlinkSerializable + Debug>(
        &mut self,
        payload: I,
        dump: bool,
        deadline: Instant,
        visit: &mut dyn FnMut(u16, &[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let socket = match self.socket.take() {
            Some(socket) => socket,
            None => open(self.protocol)?,
        };
        self.seq = self.seq.wrapping_add(1).max(1);
        match exchange(&socket, self.seq, payload, dump, deadline, visit) {
            Ok(answer) => {
                self.socket = Some(socket);
                answer
            }
            Err(error) => {
                log::debug!("netlink request failed, reopening: {error}");
                Err(errno(libc::ETIMEDOUT))
            }
        }
    }
}

// kernel: (K29, K30) net/netlink/af_netlink.c netlink_unicast, netlink_ack,
// netlink_dump_done; replies carry the request's nlmsg_seq
/// One round trip: the outer error is the transport's, the inner one the
/// kernel's answer.
fn exchange<I: NetlinkSerializable + Debug>(
    socket: &Socket,
    seq: u32,
    payload: I,
    dump: bool,
    deadline: Instant,
    visit: &mut dyn FnMut(u16, &[u8]) -> io::Result<()>,
) -> io::Result<io::Result<()>> {
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | if dump { NLM_F_DUMP } else { NLM_F_ACK };
    header.sequence_number = seq;
    let mut message = NetlinkMessage::new(header, NetlinkPayload::InnerMessage(payload));
    message.finalize();
    let mut buffer = vec![0; message.buffer_len()];
    message.serialize(&mut buffer);
    socket.send(&buffer, 0)?;
    let mut answer = Ok(());
    loop {
        let (datagram, from) = match socket.recv_from_full() {
            Ok(received) => received,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait(socket, deadline)?;
                continue;
            }
            Err(error) => return Err(error),
        };
        if from.port_number() != 0 {
            continue; // E22
        }
        for msg in messages(&datagram)? {
            if msg.seq != seq {
                continue; // a reply to an earlier, abandoned request
            }
            if msg.flags & NLM_F_DUMP_INTR != 0 && answer.is_ok() {
                answer = Err(errno(libc::EINTR));
            }
            match msg.kind {
                NLMSG_ERROR => {
                    let code = ErrorBuffer::new_checked(msg.payload)
                        .map_err(|_| errno(libc::EPROTO))?
                        .code();
                    return Ok(answer.and(code.map_or(Ok(()), |c| Err(errno(-c.get())))));
                }
                NLMSG_DONE => {
                    let code = DoneBuffer::new_checked(msg.payload).map_or(0, |d| d.code());
                    return Ok(answer.and(if code == 0 { Ok(()) } else { Err(errno(-code)) }));
                }
                kind if kind >= NLMSG_MIN_TYPE && answer.is_ok() => {
                    answer = visit(kind, msg.payload);
                }
                _ => {} // NLMSG_NOOP, NLMSG_OVERRUN, or after an error
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // kernel: include/uapi/linux/netlink.h NLMSG_ALIGN (K29)
    fn message(kind: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let len = HEADER + payload.len();
        let mut out = Vec::new();
        out.extend_from_slice(&(len as u32).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(&0u16.to_ne_bytes());
        out.extend_from_slice(&seq.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(payload);
        out.resize(len.next_multiple_of(4), 0);
        out
    }

    // kernel: include/uapi/linux/netlink.h NLMSG_ALIGN (K29)
    /// spec: K29
    #[test]
    fn a_datagram_splits_into_padded_messages() {
        let mut datagram = message(16, 7, &[1, 2, 3]);
        datagram.extend(message(3, 7, &[0; 4]));
        let parts = messages(&datagram).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(
            (parts[0].kind, parts[0].seq, parts[0].payload),
            (16, 7, &[1, 2, 3][..])
        );
        assert_eq!(parts[1].kind, NLMSG_DONE);
        let mut broken = message(16, 7, &[1, 2, 3]);
        broken[0] = 200; // a length beyond the datagram
        assert_eq!(
            messages(&broken).err().and_then(|e| e.raw_os_error()),
            Some(libc::EPROTO)
        );
    }

    // kernel: net/netlink/af_netlink.c netlink_poll (K29)
    /// spec: A14, E21
    #[test]
    fn a_passed_deadline_times_out_without_waiting() {
        let socket = open(netlink_sys::protocols::NETLINK_ROUTE).unwrap();
        let start = Instant::now();
        wait(&socket, start + Duration::from_millis(20)).unwrap();
        assert!(start.elapsed() >= Duration::from_millis(20));
        let error = wait(&socket, start).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ETIMEDOUT));
    }
}
