//! Controlled DNS and RA wire fixtures shared by adapter and process scenarios.
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv6Addr, SocketAddrV6, UdpSocket};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

pub fn advertise(sender: &Socket, destination: SocketAddrV6, servers: &[(Ipv6Addr, u32)]) {
    let mut packet = vec![134, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for (server, lifetime) in servers {
        packet.extend([25, 3, 0, 0]);
        packet.extend(lifetime.to_be_bytes());
        packet.extend(server.octets());
    }
    sender.send_to(&packet, &destination.into()).unwrap();
}

pub struct Dns {
    pub mode: Arc<AtomicUsize>,
    pub calls: Arc<AtomicUsize>,
    #[allow(dead_code)] // Some profiles need only the total count.
    pub requests: Arc<Mutex<Vec<(u16, std::time::Instant)>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Dns {
    pub fn new(address: &str, interface: &str) -> Self {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        socket.bind_device(Some(interface.as_bytes())).unwrap();
        socket
            .bind(&SocketAddrV6::new(address.parse().unwrap(), 53, 0, 0).into())
            .unwrap();
        let socket: UdpSocket = socket.into();
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .unwrap();
        let reader = socket;
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let mode = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let (policy, count) = (mode.clone(), calls.clone());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let thread = std::thread::spawn(move || {
            let mut packet = [0; 512];
            while !done.load(Ordering::SeqCst) {
                let (len, peer) = match reader.recv_from(&mut packet) {
                    Ok(packet) => packet,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => panic!("DNS fixture receive: {error}"),
                };
                let query = &packet[..len];
                let qtype = u16::from_be_bytes(query[len - 4..len - 2].try_into().unwrap());
                recorded
                    .lock()
                    .unwrap()
                    .push((qtype, std::time::Instant::now()));
                count.fetch_add(1, Ordering::SeqCst);
                let mode = policy.load(Ordering::SeqCst);
                let failure = mode == 1 || (mode == 3 && qtype == 28);
                let negative = mode == 2;
                let mut reply = query.to_vec();
                reply[2..4].copy_from_slice(&[
                    0x81,
                    if failure {
                        0x82
                    } else if negative {
                        0x83
                    } else {
                        0x80
                    },
                ]);
                if !failure && !negative {
                    reply[6..8].copy_from_slice(&1u16.to_be_bytes());
                    reply.extend([0xc0, 0x0c]);
                    reply.extend(qtype.to_be_bytes());
                    reply.extend([0, 1, 0, 0, 0, 30]);
                    if qtype == 1 {
                        reply.extend([0, 4, 192, 0, 2, 9]);
                    } else {
                        reply.extend([0, 16]);
                        reply.extend("2001:db8::9".parse::<Ipv6Addr>().unwrap().octets());
                    }
                }
                reader.send_to(&reply, peer).unwrap();
            }
        });
        Self {
            mode,
            calls,
            requests,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Dns {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.thread.take().unwrap().join();
    }
}
