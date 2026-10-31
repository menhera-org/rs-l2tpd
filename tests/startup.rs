//! Startup resource faults run separately from concurrent fake socket owners.
use std::os::fd::AsRawFd;
use std::time::Duration;

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
    // Both prctl calls affect only this subprocess. The kernel copies the
    // initialized filter while its backing allocation is still alive.
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
            libc::prctl(
                libc::PR_SET_SECCOMP,
                2 as libc::c_ulong,
                &program as *const _,
                0 as libc::c_ulong,
                0 as libc::c_ulong
            ),
            0
        );
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
            _ => panic!("unknown startup fault: {fault}"),
        };
        let (error, returned) = result.unwrap_err();
        let Error::Io(error) = error else {
            panic!("expected I/O error: {error}")
        };
        assert_eq!(
            error.raw_os_error(),
            Some(if fault == "service-engine" {
                libc::EMFILE
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
    for fault in ["runtime-thread", "service-thread", "service-engine"] {
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
