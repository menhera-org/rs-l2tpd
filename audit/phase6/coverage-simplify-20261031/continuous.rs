use std::os::unix::process::CommandExt;
unsafe extern "C" {
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn _exit(status: i32) -> !;
}
#[inline(never)]
fn child_only() {
    println!("child path");
}
#[inline(never)]
fn before_exec() {
    println!("exec path");
}
#[inline(never)]
fn after_exec() {
    println!("replacement path");
}
fn main() {
    if std::env::args().nth(1).as_deref() == Some("after-exec") {
        after_exec();
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("exec-self") {
        before_exec();
        panic!(
            "exec failed: {}",
            std::process::Command::new(std::env::current_exe().unwrap())
                .arg("after-exec")
                .exec()
        );
    }
    if std::env::args().nth(1).as_deref() == Some("exec") {
        before_exec();
        panic!(
            "exec failed: {}",
            std::process::Command::new("/usr/bin/true").exec()
        );
    }
    let pid = unsafe { fork() };
    assert!(pid >= 0);
    if pid == 0 {
        child_only();
        unsafe { _exit(0) }
    }
    let mut status = 0;
    assert_eq!(unsafe { waitpid(pid, &mut status, 0) }, pid);
    assert_eq!(status, 0);
}
