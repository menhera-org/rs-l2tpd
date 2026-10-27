//! Shared construction of multicast sockets, tuned before notifications start.

use futures_util::Stream;
use log::{debug, warn};
use rtnetlink::{
    packet_core::NetlinkMessage,
    packet_route::RouteNetlinkMessage,
    proto::Connection,
    sys::{AsyncSocket, Socket, SocketAddr},
    Handle, MulticastGroup,
};
use std::io;

/// Linux doubles SO_RCVBUF to account for skb bookkeeping. This request
/// therefore permits up to 16 MiB of queued kernel memory per monitor; it
/// does not allocate that memory eagerly or change a global kernel limit.
const REQUESTED_RECEIVE_BUFFER: usize = 8 * 1024 * 1024;

// Keep rtnetlink's constructor shape without adding a concrete channel dependency.
#[allow(clippy::type_complexity)]
pub(crate) fn multicast_connection(
    groups: &[MulticastGroup],
    purpose: &str,
) -> io::Result<(
    Connection<RouteNetlinkMessage>,
    Handle,
    impl Stream<Item = (NetlinkMessage<RouteNetlinkMessage>, SocketAddr)> + Unpin + Send + 'static,
)> {
    let (mut connection, mut handle, mut messages) = rtnetlink::new_connection()?;
    let previous = connection.socket_mut().socket_mut().get_rx_buf_sz().ok();
    if let Some(previous) = previous.filter(|size| *size < REQUESTED_RECEIVE_BUFFER * 2) {
        // Keep an untouched default socket until tuning has proved useful.
        // A host can have rmem_default > rmem_max; SO_RCVBUF would then shrink
        // its default, and an unavailable FORCE option could not restore it.
        match rtnetlink::new_connection() {
            Ok((mut candidate, candidate_handle, candidate_messages)) => {
                let socket = candidate.socket_mut().socket_mut();
                tune_receive_buffer(socket, purpose);
                if prefer_tuned_buffer(previous, socket.get_rx_buf_sz().ok()) {
                    (connection, handle, messages) =
                        (candidate, candidate_handle, candidate_messages);
                } else {
                    debug!("{purpose} keeps its original {previous}-byte receive buffer");
                }
            }
            Err(error) => debug!(
                "could not prepare a larger {purpose} receive buffer: {error}; keeping the default"
            ),
        }
    } else {
        debug!("{purpose} keeps its original receive buffer: {previous:?}");
    }
    let socket = connection.socket_mut().socket_mut();

    // Match rtnetlink's multicast constructor, but tune the socket before
    // either bind or membership starts delivering notifications.
    let group_mask = groups
        .iter()
        .filter(|group| !group.need_via_add_membership())
        .fold(0, |mask, group| mask | (1 << (*group as u32 - 1)));
    socket.bind(&SocketAddr::new(0, group_mask))?;
    for group in groups
        .iter()
        .filter(|group| group.need_via_add_membership())
    {
        socket.add_membership(*group as u32)?;
    }
    Ok((connection, handle, messages))
}

fn prefer_tuned_buffer(previous: usize, tuned: Option<usize>) -> bool {
    tuned.is_some_and(|size| size >= previous)
}

fn tune_receive_buffer(socket: &Socket, purpose: &str) {
    let previous = socket.get_rx_buf_sz().ok();
    let target = REQUESTED_RECEIVE_BUFFER * 2;
    // A host may deliberately provide an even larger default. Never reduce it.
    if previous.is_some_and(|size| size >= target) {
        debug!(
            "{purpose} receive buffer already has {} bytes",
            previous.unwrap()
        );
        return;
    }

    if let Err(error) = socket.set_rx_buf_sz(REQUESTED_RECEIVE_BUFFER as libc::c_int) {
        warn!("failed to enlarge {purpose} receive buffer: {error}; continuing");
    }
    let ordinary = socket.get_rx_buf_sz().ok();
    if ordinary.is_none_or(|size| size < target) {
        // CAP_NET_ADMIN is already needed for daemon kernel operations.
        // Its absence, a seccomp policy, or a lower resource limit must not
        // turn this optional tuning into a new startup requirement.
        if let Err(error) = nix::sys::socket::setsockopt(
            socket,
            nix::sys::socket::sockopt::RcvBufForce,
            &REQUESTED_RECEIVE_BUFFER,
        ) {
            debug!("could not bypass the per-socket receive-buffer cap for {purpose}: {error}");
        }
    }
    match socket.get_rx_buf_sz() {
        Ok(effective) => debug!(
            "{purpose} receive buffer requested={} effective={} previous={previous:?} ordinary={ordinary:?}",
            REQUESTED_RECEIVE_BUFFER, effective
        ),
        Err(error) => debug!("could not read {purpose} receive buffer size: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamped_or_unmeasurable_tuning_keeps_a_larger_original_buffer() {
        assert!(!prefer_tuned_buffer(1024 * 1024, Some(425984)));
        assert!(!prefer_tuned_buffer(212992, None));
        assert!(prefer_tuned_buffer(212992, Some(425984)));
        assert!(prefer_tuned_buffer(212992, Some(212992)));
    }

    #[tokio::test]
    async fn receive_buffer_tuning_is_bounded_and_needs_no_capability() {
        let baseline = Socket::new(rtnetlink::sys::protocols::NETLINK_ROUTE).unwrap();
        let before = baseline.get_rx_buf_sz().unwrap();
        let (mut connection, _handle, _messages) =
            multicast_connection(&[], "test monitor").unwrap();
        let after = connection
            .socket_mut()
            .socket_mut()
            .get_rx_buf_sz()
            .unwrap();
        assert!(
            after >= before,
            "buffer tuning must not shrink the kernel default"
        );
        assert!(after <= before.max(REQUESTED_RECEIVE_BUFFER * 2));
        eprintln!("netlink receive buffer: before={before} effective={after} requested={REQUESTED_RECEIVE_BUFFER}");
    }
}
