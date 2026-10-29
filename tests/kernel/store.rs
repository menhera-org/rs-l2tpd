//! Two halves of the real-manager reference test. The user service holds
//! only a Unix transport; the isolated container owns all network objects.
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
use rs_l2tpd::kernel::{Family, Kernel};
use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::{Duration, Instant};

fn notify(arguments: &[&str]) {
    assert!(
        std::process::Command::new("systemd-notify")
            .args(arguments)
            .status()
            .unwrap()
            .success()
    );
}

/// spec: L13, P14, K37
#[test]
#[ignore = "run as a user systemd notify service, see tests/kernel/README.md"]
fn manager_bridge() {
    let path = std::env::var("TRANSFER_SOCKET").unwrap();
    let listener = UnixListener::bind(&path).unwrap();
    notify(&["--ready"]);
    let (mut stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut byte = [0];
    let mut iov = [IoSliceMut::new(&mut byte)];
    let mut control = nix::cmsg_space!([i32; 1]);
    let message = recvmsg::<()>(
        stream.as_raw_fd(),
        &mut iov,
        Some(&mut control),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )
    .unwrap();
    let descriptor = message
        .cmsgs()
        .unwrap()
        .find_map(|cmsg| match cmsg {
            ControlMessageOwned::ScmRights(mut fds) => Some(fds.remove(0)),
            _ => None,
        })
        .unwrap();
    // SCM_RIGHTS gave this fixture unique ownership of a new descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(descriptor) };
    nix::fcntl::fcntl(
        &fd,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
    )
    .unwrap();
    let number = fd.as_raw_fd().to_string();
    notify(&["--fd", &number, "--fdname=t9381", "FDSTORE=1"]);
    drop(fd);
    stream.write_all(b"S").unwrap();
    stream.read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"C");
    // systemd-notify's default processing barrier, never --no-block.
    notify(&["FDSTOREREMOVE=1", "FDNAME=t9381"]);
    stream.write_all(b"R").unwrap();
    stream.read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"D");
    std::fs::remove_file(path).unwrap();
}

/// spec: L13, P14, K17, K37
#[test]
#[ignore = "isolated privileged container connected to manager_bridge"]
fn kernel_reference() {
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
    let mut kernel = rs_l2tpd::kernel::linux::LinuxKernel::new().unwrap();
    let socket = kernel.create_socket(Family::V6, 9381, 9382).unwrap();
    kernel.register_tunnel(socket, 9381, 9382).unwrap();
    let fd = kernel.clone_fd(socket).unwrap();
    let mut stream = UnixStream::connect(std::env::var("TRANSFER_SOCKET").unwrap()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    sendmsg::<()>(
        stream.as_raw_fd(),
        &[IoSlice::new(b"F")],
        &[ControlMessage::ScmRights(&[fd.as_raw_fd()])],
        MsgFlags::empty(),
        None,
    )
    .unwrap();
    drop(fd);
    let mut byte = [0];
    stream.read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"S");
    kernel.close(socket);
    assert!(
        kernel.tunnel(9381).unwrap().is_some(),
        "the manager owns the only remaining reference"
    );
    stream.write_all(b"C").unwrap();
    stream.read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"R");
    let deadline = Instant::now() + Duration::from_secs(2);
    while kernel.tunnel(9381).unwrap().is_some() {
        assert!(
            Instant::now() < deadline,
            "withdrawal must release the actual socket"
        );
        std::thread::yield_now();
    }
    stream.write_all(b"D").unwrap();
}
