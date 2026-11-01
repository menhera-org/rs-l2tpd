//! Startup resource faults run separately from concurrent fake socket owners.
use std::os::fd::AsRawFd;
use std::time::Duration;

use nix::libc;

use rs_l2tpd::config::Config;
use rs_l2tpd::kernel::fake::FakeKernel;
use rs_l2tpd::reconciler::IphostResolve;
use rs_l2tpd::runtime::{AdoptedSocket, Runtime};
use rs_l2tpd::{Error, service};

#[path = "tools/syscall_fault.rs"]
mod syscall_fault;
use syscall_fault::refuse as refuse_startup_syscalls;

fn test_name(name: &str) -> String {
    match module_path!().split_once("::") {
        Some((_, module)) => format!("{module}::{name}"),
        None => name.to_owned(),
    }
}

/// spec: L13, P14, G23
#[test]
#[cfg_attr(
    coverage_nightly,
    ignore = "serial coverage profile: child processes inherit concurrent fake descriptors"
)]
fn descriptor_resource_failures_preserve_inheritance_and_release_partial_sockets() {
    const CHILD: &str = "PHASE6_DESCRIPTOR_FAULT";
    if let Ok(case) = std::env::var(CHILD) {
        use rs_l2tpd::config::TunnelConfig;
        use rs_l2tpd::kernel::{Family, Kernel};
        use rs_l2tpd::reconciler::Reconciler;
        use std::os::fd::{AsFd, BorrowedFd};
        // opendir inspects metadata; keep this enumeration open before denying it.
        let directory = unsafe { libc::opendir(c"/proc/self/fd".as_ptr()) };
        assert!(!directory.is_null());
        let count = || unsafe {
            libc::rewinddir(directory);
            let mut count = 0;
            while !libc::readdir(directory).is_null() {
                count += 1;
            }
            assert!(count >= 5);
            count
        };
        if case == "inherited-duplicate" {
            let (fd, peer) = std::os::unix::net::UnixStream::pair().unwrap();
            let raw = fd.as_raw_fd();
            let mut r = Reconciler::new(FakeKernel::new(7), Box::new(IphostResolve::default()));
            r.inherit("t10".into(), fd.into());
            let mut config = Config::new();
            config
                .insert_tunnel(
                    "a",
                    TunnelConfig::builder(10)
                        .ip_version(Family::V6)
                        .build()
                        .unwrap(),
                )
                .unwrap();
            refuse_startup_syscalls(&[libc::SYS_fcntl], libc::EMFILE);
            assert!(!r.reconcile(config));
            assert!(!r.ready());
            assert_eq!(r.kernel().open_sockets(), 0);
            assert!(r.take_requests().is_empty());
            // The original remains readable even though every duplication fails.
            let borrowed = unsafe { BorrowedFd::borrow_raw(raw) };
            assert_eq!(
                unsafe { libc::write(peer.as_fd().as_raw_fd(), c"alive".as_ptr().cast(), 5) },
                5
            );
            let mut bytes = [0u8; 5];
            assert_eq!(
                unsafe { libc::read(borrowed.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) },
                5
            );
            assert_eq!(&bytes, b"alive");
            assert!(r.shutdown());
            assert_eq!(
                unsafe { libc::read(raw, bytes.as_mut_ptr().cast(), bytes.len()) },
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EBADF)
            );
        } else {
            let mut k = FakeKernel::new(7);
            match case.as_str() {
                "socket-duplicate" => refuse_startup_syscalls(&[libc::SYS_fcntl], libc::EMFILE),
                "socket-metadata" => {
                    refuse_startup_syscalls(&[libc::SYS_fstat, libc::SYS_statx], libc::EIO)
                }
                _ => panic!("unknown descriptor fault"),
            }
            let before = count();
            assert_eq!(
                k.create_socket(Family::V6, 10, 20)
                    .unwrap_err()
                    .raw_os_error(),
                Some(if case == "socket-duplicate" {
                    libc::EMFILE
                } else {
                    libc::EIO
                })
            );
            assert_eq!(k.open_sockets(), 0);
            assert_eq!(count(), before);
        }
        assert_eq!(unsafe { libc::closedir(directory) }, 0);
        println!("DESCRIPTOR_FAULT_CHECKED={case}");
        return;
    }
    for case in ["inherited-duplicate", "socket-duplicate", "socket-metadata"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &test_name(
                    "descriptor_resource_failures_preserve_inheritance_and_release_partial_sockets",
                ),
                "--include-ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, case)
            .output()
            .unwrap();
        assert!(output.status.success(), "{case}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains(&format!("DESCRIPTOR_FAULT_CHECKED={case}"))
        );
        assert!(!String::from_utf8_lossy(&output.stderr).contains("LLVM Profile Error"));
        println!("DESCRIPTOR_FAULT_VERIFIED={case}");
    }
}

/// spec: V3, V4, V15, A9, G23
#[test]
#[cfg_attr(
    coverage_nightly,
    ignore = "serial coverage profile: child processes inherit concurrent fake descriptors"
)]
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
                &test_name("resolver_spawn_failures_return_errors_and_release_worker_permits"),
                "--include-ignored",
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
#[cfg_attr(
    coverage_nightly,
    ignore = "serial coverage profile: child processes inherit concurrent fake descriptors"
)]
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
                &test_name("startup_resource_failures_return_errors_and_preserve_adopted_fds"),
                "--include-ignored",
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
