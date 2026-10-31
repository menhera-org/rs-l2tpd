use nix::sys::signal::SigSet;

#[path = "../../../tests/tools/syscall_fault.rs"]
mod syscall_fault;

fn main() {
    syscall_fault::refuse(&[nix::libc::SYS_rt_sigprocmask], nix::libc::EIO);
    let result = SigSet::empty().thread_set_mask();
    println!("REFUSED_MASK_RESULT={result:?}");
    assert_eq!(result, Err(nix::errno::Errno::EIO));
}
