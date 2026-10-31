//! Startup resource faults run separately from concurrent fake socket owners.
use std::os::fd::AsRawFd;
use std::time::Duration;

use nix::libc;

use rs_l2tpd::config::Config;
use rs_l2tpd::kernel::fake::FakeKernel;
use rs_l2tpd::reconciler::IphostResolve;
use rs_l2tpd::runtime::{AdoptedSocket, Runtime};
use rs_l2tpd::{Error, service};

// Test-only fault injection: include/uapi/linux/seccomp.h and filter.h.
// The child and its future worker do not exec; syscall numbers use its target ABI.
fn refuse_startup_syscalls(syscalls: &[libc::c_long], errno: i32) {
    let mut filter = vec![libc::sock_filter {
        code: 0x20,
        jt: 0,
        jf: 0,
        k: 0,
    }];
    for syscall in syscalls {
        filter.push(libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: (*syscall).try_into().unwrap(),
        });
        filter.push(libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x00050000 | u32::try_from(errno).unwrap(),
        });
    }
    filter.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x7fff0000,
    });
    let program = libc::sock_fprog {
        len: filter.len().try_into().unwrap(),
        filter: filter.as_mut_ptr(),
    };
    // TSYNC also covers an already-started dispatcher in this subprocess.
    // The kernel copies the filter while its allocation is still alive.
    unsafe {
        assert_eq!(
            libc::prctl(
                libc::PR_SET_NO_NEW_PRIVS,
                1 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong
            ),
            0
        );
        assert_eq!(
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                libc::SECCOMP_FILTER_FLAG_TSYNC,
                &program as *const _,
            ),
            0
        );
    }
}

/// spec: V3, V4, V15, A9, G23
#[test]
fn resolver_spawn_failures_return_errors_and_release_worker_permits() {
    use rs_l2tpd::reconciler::{Lookup, Resolve, ResolverSpec};
    const CHILD: &str = "RS_L2TPD_TEST_RESOLVER_SPAWN_FAILURE";
    if let Ok(fault) = std::env::var(CHILD) {
        let mut resolver = IphostResolve::default();
        let lookup = |id, octet| Lookup::new(id, format!("192.0.2.{octet}"), ResolverSpec::System);
        if fault == "owner" {
            refuse_startup_syscalls(&[libc::SYS_clone, libc::SYS_clone3], libc::EAGAIN);
            let error = resolver.watch(lookup(1, 1)).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EAGAIN));
            assert!(resolver.poll().is_empty());
            assert!(!resolver.retry_discovery(1));
            resolver.unwatch(1);
        } else {
            assert_eq!(fault, "worker");
            resolver.watch(lookup(1, 1)).unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                let answers = resolver.poll();
                if !answers.is_empty() {
                    assert_eq!(answers, [(1, vec!["192.0.2.1".parse().unwrap()])]);
                    break;
                }
                assert!(std::time::Instant::now() < deadline);
                std::thread::yield_now();
            }
            refuse_startup_syscalls(&[libc::SYS_clone, libc::SYS_clone3], libc::EAGAIN);
            // More than the eight-slot budget: every failed spawn must return
            // its permit so all sixteen jobs can complete with empty results.
            for id in 2..18 {
                resolver.watch(lookup(id, id)).unwrap();
            }
            let mut answers = std::collections::BTreeMap::new();
            while answers.len() < 16 {
                answers.extend(resolver.poll());
                assert!(
                    std::time::Instant::now() < deadline,
                    "stranded worker permit"
                );
                std::thread::yield_now();
            }
            assert_eq!(
                answers.keys().copied().collect::<Vec<_>>(),
                (2..18).collect::<Vec<_>>()
            );
            assert!(answers.values().all(Vec::is_empty));
            for id in 1..18 {
                resolver.unwatch(id);
            }
            assert!(resolver.poll().is_empty());
        }
        println!("RESOLVER_SPAWN_CHECKED={fault}");
        return;
    }
    for fault in ["owner", "worker"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "resolver_spawn_failures_return_errors_and_release_worker_permits",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, fault)
            .output()
            .unwrap();
        assert!(output.status.success(), "{fault}: {output:?}");
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains(&format!("RESOLVER_SPAWN_CHECKED={fault}"))
        );
        println!("RESOLVER_SPAWN_VERIFIED={fault}");
    }
}

/// spec: L5, L9, G14
#[test]
fn startup_resource_failures_return_errors_and_preserve_adopted_fds() {
    const CHILD: &str = "RS_L2TPD_TEST_STARTUP_FAILURE";
    if let Ok(fault) = std::env::var(CHILD) {
        use std::io::{Read, Write};
        let engine = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _entered = engine.enter();
        let mut peers = std::collections::BTreeMap::new();
        let mut adopted = Vec::new();
        for name in ["malformed inherited name", "t7"] {
            let (fd, peer) = std::os::unix::net::UnixStream::pair().unwrap();
            peers.insert(name.to_owned(), (fd.as_raw_fd(), peer));
            adopted.push(AdoptedSocket::new(name, fd.into()));
        }
        let result = match fault.as_str() {
            "runtime-thread" => {
                refuse_startup_syscalls(&[libc::SYS_clone, libc::SYS_clone3], libc::EAGAIN);
                Runtime::with_kernel(
                    FakeKernel::new(42),
                    Box::new(IphostResolve::default()),
                    adopted,
                )
                .map(|_| ())
            }
            "service-thread" | "service-engine" => {
                let runtime = Runtime::with_kernel(
                    FakeKernel::new(42),
                    Box::new(IphostResolve::default()),
                    adopted,
                )
                .unwrap();
                if fault == "service-thread" {
                    refuse_startup_syscalls(&[libc::SYS_clone, libc::SYS_clone3], libc::EAGAIN);
                } else {
                    refuse_startup_syscalls(&[libc::SYS_epoll_create1], libc::EMFILE);
                }
                service::Service::with_runtime(Config::new(), runtime).map(|_| ())
            }
            "blocking-thread" | "blocking-engine" | "blocking-open" => {
                match fault.as_str() {
                    "blocking-thread" => {
                        refuse_startup_syscalls(&[libc::SYS_clone, libc::SYS_clone3], libc::EAGAIN);
                    }
                    "blocking-engine" => {
                        refuse_startup_syscalls(&[libc::SYS_epoll_create1], libc::EMFILE);
                    }
                    "blocking-open" => refuse_startup_syscalls(&[libc::SYS_socket], libc::EPERM),
                    _ => unreachable!(),
                }
                if fault == "blocking-open" {
                    rs_l2tpd::blocking::Service::new(Config::new(), adopted).map(|_| ())
                } else {
                    rs_l2tpd::blocking::Service::with_kernel(
                        Config::new(),
                        FakeKernel::new(42),
                        Box::new(IphostResolve::default()),
                        adopted,
                    )
                    .map(|_| ())
                }
            }
            _ => panic!("unknown startup fault: {fault}"),
        };
        let (error, returned) = result.unwrap_err();
        let Error::Io(error) = error else {
            panic!("expected I/O error: {error}")
        };
        assert_eq!(
            error.raw_os_error(),
            Some(if fault.ends_with("engine") {
                libc::EMFILE
            } else if fault == "blocking-open" {
                libc::EPERM
            } else {
                libc::EAGAIN
            })
        );
        assert_eq!(returned.len(), peers.len());
        for socket in returned {
            let (name, fd) = socket.into_parts();
            let (original, mut peer) = peers.remove(&name).unwrap();
            assert_eq!(fd.as_raw_fd(), original);
            peer.write_all(b"alive").unwrap();
            let mut stream = std::os::unix::net::UnixStream::from(fd);
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut bytes = [0; 5];
            stream.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"alive");
        }
        assert!(peers.is_empty());
        println!("STARTUP_FAILURE_CHECKED={fault}");
        return;
    }
    for fault in [
        "runtime-thread",
        "service-thread",
        "service-engine",
        "blocking-thread",
        "blocking-engine",
        "blocking-open",
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "startup_resource_failures_return_errors_and_preserve_adopted_fds",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, fault)
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout.clone()).unwrap();
        assert!(output.status.success(), "{fault}: {output:?}");
        assert!(
            stdout.contains(&format!("STARTUP_FAILURE_CHECKED={fault}")),
            "{output:?}"
        );
        println!("STARTUP_FAILURE_VERIFIED={fault}");
    }
}
