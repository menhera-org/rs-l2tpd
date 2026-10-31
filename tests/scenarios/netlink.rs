//! Fixture-only netlink observation. No request adapter is added to the daemon.
// Kernel: Linux v6.8 net/netlink/af_netlink.c __netlink_deliver_tap_skb
// preserves the netlink datagram and puts its protocol in sll_protocol;
// net/packet/af_packet.c packet_recvmsg/packet_getsockopt provide capture/drop
// accounting. include/uapi/linux/netlink.h defines the aligned message header.
use super::support::Pair;
use netlink_packet_core::NetlinkBuffer;
use std::io;
use std::os::fd::AsRawFd;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Default)]
pub struct Counts {
    pub requests: usize,
    pub route_queries: usize,
    pub generic_requests: usize,
    pub packets: u32,
}
pub struct RouteTrace {
    stop: Arc<AtomicBool>,
    counts: Arc<Mutex<Counts>>,
    reader: Option<std::thread::JoinHandle<io::Result<[u32; 2]>>>,
}
fn requests(protocol: u16, bytes: &[u8]) -> io::Result<(usize, usize)> {
    let mut rest = bytes;
    let (mut requests, mut routes) = (0, 0);
    while !rest.is_empty() {
        let header = NetlinkBuffer::new_checked(rest)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "nlmon header"))?;
        if header.flags() & netlink_packet_core::NLM_F_REQUEST != 0 {
            requests += 1;
            routes += usize::from(protocol == 0 && header.message_type() == 26); // RTM_GETROUTE
        }
        let length = header.length() as usize;
        rest = rest.get(length.next_multiple_of(4)..).unwrap_or_default();
    }
    Ok((requests, routes))
}
impl RouteTrace {
    pub fn start(pair: &Pair, side: usize) -> Self {
        assert!(
            std::path::Path::new("/sys/module/nlmon").exists()
                || std::env::var("RS_L2TPD_BUILTIN_NLMON").as_deref() == Ok("1"),
            "nlmon must already be available; the fixture never loads host modules"
        );
        pair.ip(side, &["link", "add", "nltrace", "type", "nlmon"]);
        pair.ip(side, &["link", "set", "nltrace", "up"]);
        let index = pair.index(side, "nltrace");
        let original = std::fs::File::open("/proc/self/ns/net").unwrap();
        let target = std::fs::File::open(format!("/run/netns/{}", pair.names[side])).unwrap();
        nix::sched::setns(target, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
        let opened = (|| -> io::Result<socket2::Socket> {
            let socket = socket2::Socket::new(
                socket2::Domain::PACKET,
                socket2::Type::RAW,
                Some(socket2::Protocol::from(i32::from(3u16.to_be()))),
            )?;
            socket.set_recv_buffer_size(8 << 20)?;
            socket.set_read_timeout(Some(Duration::from_millis(100)))?;
            // Kernel UAPI sockaddr_ll is an initialized POD address; bind reads
            // exactly its size and the packet socket is owned by this scope.
            let address = libc::sockaddr_ll {
                sll_family: libc::AF_PACKET as u16,
                sll_protocol: 3u16.to_be(),
                sll_ifindex: index as i32,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0; 8],
            };
            let result = unsafe {
                libc::bind(
                    socket.as_raw_fd(),
                    (&address as *const libc::sockaddr_ll).cast(),
                    std::mem::size_of_val(&address) as libc::socklen_t,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(socket)
        })();
        nix::sched::setns(original, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
        let socket = opened.unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let counts = Arc::new(Mutex::new(Counts::default()));
        let captured = counts.clone();
        let reader = std::thread::spawn(move || {
            let mut bytes = [0u8; 65536];
            loop {
                let mut address = libc::sockaddr_ll {
                    sll_family: 0,
                    sll_protocol: 0,
                    sll_ifindex: 0,
                    sll_hatype: 0,
                    sll_pkttype: 0,
                    sll_halen: 0,
                    sll_addr: [0; 8],
                };
                let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
                // The receive buffer/address are initialized and writable; the
                // returned length is checked before any byte is inspected.
                let received = unsafe {
                    libc::recvfrom(
                        socket.as_raw_fd(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                        libc::MSG_TRUNC,
                        (&mut address as *mut libc::sockaddr_ll).cast(),
                        &mut length,
                    )
                };
                if received < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    if error.kind() != io::ErrorKind::WouldBlock {
                        return Err(error);
                    }
                    if done.load(Ordering::SeqCst) {
                        break;
                    }
                    continue;
                }
                let received = received as usize;
                if received > bytes.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "truncated nlmon packet",
                    ));
                }
                let protocol = u16::from_be(address.sll_protocol);
                let (requests, routes) = requests(protocol, &bytes[..received])?;
                let mut state = captured.lock().unwrap();
                state.packets += 1;
                state.requests += requests;
                state.route_queries += routes;
                state.generic_requests += if protocol == 16 { requests } else { 0 };
            }
            let mut statistics = [0u32; 2];
            let mut length = std::mem::size_of_val(&statistics) as libc::socklen_t;
            // Default TPACKET_V1 PACKET_STATISTICS is two u32 counters.
            let result = unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_PACKET,
                    libc::PACKET_STATISTICS,
                    statistics.as_mut_ptr().cast(),
                    &mut length,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            assert_eq!(length as usize, std::mem::size_of_val(&statistics));
            Ok(statistics)
        });
        Self {
            stop,
            counts,
            reader: Some(reader),
        }
    }
    pub fn snapshot(&self) -> Counts {
        *self.counts.lock().unwrap()
    }
    pub fn finish(mut self) -> Counts {
        self.stop.store(true, Ordering::SeqCst);
        let statistics = self.reader.take().unwrap().join().unwrap().unwrap();
        let counts = self.snapshot();
        assert_eq!(statistics[1], 0, "nlmon capture lost packets");
        assert_eq!(
            counts.packets, statistics[0],
            "all captured packets must be read"
        );
        counts
    }
}
impl Drop for RouteTrace {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[test]
fn netlink_requests_are_counted_without_counting_notifications_or_replies() {
    let mut query = [0u8; 16];
    query[..4].copy_from_slice(&16u32.to_ne_bytes());
    query[4..6].copy_from_slice(&26u16.to_ne_bytes());
    query[6..8].copy_from_slice(&1u16.to_ne_bytes());
    assert_eq!(requests(0, &query).unwrap(), (1, 1));
    assert_eq!(requests(16, &query).unwrap(), (1, 0));
    let mut reply = query;
    reply[4..6].copy_from_slice(&24u16.to_ne_bytes());
    reply[6..8].copy_from_slice(&0u16.to_ne_bytes());
    assert_eq!(requests(0, &reply).unwrap(), (0, 0));
    let datagram = [query, reply].concat();
    assert_eq!(requests(0, &datagram).unwrap(), (1, 1));
    assert!(requests(0, &query[..8]).is_err());
    query[..4].copy_from_slice(&200u32.to_ne_bytes());
    assert!(requests(0, &query).is_err());
}

#[test]
#[ignore = "disposable privileged container with nlmon already available"]
fn nlmon_sees_fixture_route_and_generic_requests_without_packet_loss() {
    let pair = Pair::new();
    pair.underlay(true, true);
    let trace = RouteTrace::start(&pair, 0);
    pair.ip(0, &["-4", "route", "get", "192.0.2.2"]);
    pair.ip(0, &["-6", "route", "get", "2001:db8:1::2"]);
    super::support::wait("both deliberate route queries captured", || {
        trace.snapshot().route_queries == 2
    });
    pair.ip(0, &["l2tp", "show", "tunnel"]);
    super::support::wait("deliberate L2TP query captured", || {
        trace.snapshot().generic_requests > 0
    });
    let counts = trace.finish();
    assert_eq!(counts.route_queries, 2);
    assert!(counts.requests >= 3 && counts.generic_requests > 0);
    println!("nlmon counts: {counts:?}");
}

fn populate_routes(pair: &Pair) {
    use std::io::Write;
    use std::process::Stdio;
    for family in ["-4", "-6"] {
        let mut child = pair
            .command(0, "ip", &[family, "-batch", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let writer = std::thread::spawn(move || {
            for n in 0..100_000u32 {
                if family == "-4" {
                    writeln!(
                        input,
                        "route add blackhole 10.{}.{}.{}/32",
                        n >> 16,
                        (n >> 8) & 255,
                        n & 255
                    )?;
                } else {
                    writeln!(
                        input,
                        "route add blackhole 2001:db8:ffff::{:x}:{:x}/128",
                        n >> 16,
                        n & 65535
                    )?;
                }
            }
            Ok::<_, io::Error>(())
        });
        let result = child.wait_with_output().unwrap();
        writer.join().unwrap().unwrap();
        assert!(result.status.success(), "{result:?}");
        let routes = pair.ip(0, &[family, "route", "show", "type", "blackhole"]);
        assert_eq!(routes.lines().count(), 100_000);
        assert!(
            pair.ip(0, &[family, "route", "show", "default"])
                .trim()
                .is_empty()
        );
    }
}

/// spec: H8
#[test]
#[ignore = "disposable privileged container with nlmon already available"]
fn large_default_free_tables_do_not_add_daemon_route_queries() {
    use super::support::config;
    use std::time::Instant;
    let pair = Pair::new();
    pair.underlay(true, true);
    let mut counts = Vec::new();
    for large in [false, true] {
        if large {
            populate_routes(&pair);
            pair.ip(0, &["link", "del", "nltrace"]);
        }
        let trace = RouteTrace::start(&pair, 0);
        let started = Instant::now();
        let mut daemon = pair.start(0, &config(0, &["192.0.2.2", "2001:db8:1::2"]));
        let ready = daemon.event("ready").duration_since(started);
        let reloaded = Instant::now();
        daemon.reload();
        let reload = reloaded.elapsed();
        // Positive controls in each capture prevent an empty trace passing.
        pair.ip(0, &["-4", "route", "get", "192.0.2.2"]);
        pair.ip(0, &["-6", "route", "get", "2001:db8:1::2"]);
        super::support::wait("route-query controls captured", || {
            trace.snapshot().route_queries >= 2
        });
        // Cleanup query counts depend on kernel worker scheduling. Compare
        // startup/reload after the capture has drained, before shutdown.
        let startup = trace.snapshot();
        daemon.stop();
        let observed = trace.finish();
        assert_eq!(observed.route_queries, 2, "only the fixture queries routes");
        println!(
            "large={large}: ready={ready:?}, reload={reload:?}, startup={startup:?}, total={observed:?}"
        );
        counts.push(startup.requests);
        pair.absent(0);
    }
    assert_eq!(
        counts[0], counts[1],
        "route-table size must not add daemon startup/reload requests"
    );
}
