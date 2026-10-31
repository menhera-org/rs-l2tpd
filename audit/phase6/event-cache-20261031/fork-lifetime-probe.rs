use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;
use rs_l2tpd::kernel::{Family, Kernel};
use rs_l2tpd::kernel::fake::FakeKernel;

unsafe extern "C" {
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn _exit(status: i32) -> !;
}

fn main() {
    let mut kernel = FakeKernel::new(42);
    let socket = kernel.create_socket(Family::V4, 10, 20).unwrap();
    kernel.register_tunnel(socket, 10, 20).unwrap();
    let (mut parent, mut child) = UnixStream::pair().unwrap();
    // Single-threaded diagnostic: retain inherited descriptors until released.
    let pid = unsafe { fork() };
    assert!(pid >= 0);
    if pid == 0 {
        drop(parent);
        child.read_exact(&mut [0]).unwrap();
        unsafe { _exit(0) }
    }
    drop(child);
    kernel.close(socket);
    kernel.advance(Duration::from_secs(2));
    kernel.tick();
    assert!(kernel.tunnel(10).unwrap().is_some());
    println!("FORK_REFERENCE=retained_after_two_virtual_seconds");
    parent.write_all(&[0]).unwrap();
    let mut status = -1;
    assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid);
    assert_eq!(status, 0);
    kernel.tick();
    assert!(kernel.tunnel(10).unwrap().is_none());
    println!("FORK_REFERENCE=released_after_child_exit");
}
