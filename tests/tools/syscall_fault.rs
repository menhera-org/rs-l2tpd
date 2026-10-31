use nix::libc;

// Test-only fault injection: include/uapi/linux/seccomp.h and filter.h.
// The child and its future worker do not exec; syscall numbers use its target ABI.
pub(crate) fn refuse(syscalls: &[libc::c_long], errno: i32) {
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
