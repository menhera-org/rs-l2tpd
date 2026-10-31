pub extern crate libc;
extern crate self as nix;
#[path = "../../../tests/tools/syscall_fault.rs"]
mod syscall_fault;

fn denied_open() -> std::io::Result<std::fs::File> {
    std::fs::File::open("/dev/null")
}

fn denied_metadata(file: &std::fs::File) -> std::io::Result<std::fs::Metadata> {
    file.metadata()
}

fn main() {
    use std::os::unix::ffi::OsStrExt;
    let path = std::env::args_os().nth(1).unwrap();
    let path = std::ffi::CString::new(path.as_bytes()).unwrap().into_raw();
    unsafe extern "C" {
        fn __llvm_profile_set_filename(path: *const libc::c_char);
    }
    unsafe {
        __llvm_profile_set_filename(path);
    }
    let held = std::fs::File::open("/dev/null").unwrap();
    syscall_fault::refuse(&[libc::SYS_openat, libc::SYS_fstat, libc::SYS_statx], libc::EACCES);
    assert_eq!(denied_open().unwrap_err().raw_os_error(), Some(libc::EACCES));
    assert_eq!(denied_metadata(&held).unwrap_err().raw_os_error(), Some(libc::EACCES));
    println!("PREOPENED_PROFILE_OPEN_REFUSED=EACCES");
}
