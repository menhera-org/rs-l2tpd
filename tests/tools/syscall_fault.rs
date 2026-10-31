use nix::libc;

#[allow(
    dead_code,
    reason = "shared helper; not every test binary denies duplication"
)]
pub(crate) fn refuse_dup2(errno: i32) {
    let syscalls = &[
        #[cfg(any(
            target_arch = "arm",
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "s390x",
            target_arch = "sparc",
            target_arch = "sparc64",
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "mips32r6",
            target_arch = "mips64r6",
            target_arch = "m68k"
        ))]
        libc::SYS_dup2,
        libc::SYS_dup3,
    ];
    refuse(syscalls, errno);
}

#[allow(
    dead_code,
    reason = "shared helper; not every test binary denies file opens"
)]
pub(crate) fn refuse_open(errno: i32) {
    let syscalls = &[
        #[cfg(any(
            target_arch = "arm",
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "s390x",
            target_arch = "sparc",
            target_arch = "sparc64",
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "mips32r6",
            target_arch = "mips64r6",
            target_arch = "m68k"
        ))]
        libc::SYS_open,
        libc::SYS_openat,
    ];
    refuse(syscalls, errno);
}

// Test-only fault injection: include/uapi/linux/seccomp.h and filter.h.
// The child and its future worker do not exec; syscall numbers use its target ABI.
pub(crate) fn refuse(syscalls: &[libc::c_long], errno: i32) {
    #[cfg(coverage_nightly)]
    keep_profile_output();
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

#[cfg(coverage_nightly)]
fn keep_profile_output() {
    unsafe extern "C" {
        fn __llvm_profile_get_filename() -> *const libc::c_char;
        fn __llvm_profile_set_filename(path: *const libc::c_char);
        fn __llvm_profile_set_file_object(file: *mut libc::FILE, merge: libc::c_int)
        -> libc::c_int;
    }
    // LLVM retains this allocated name and FILE until this fault-test child exits.
    unsafe {
        let path = __llvm_profile_get_filename();
        assert!(!path.is_null() && *path != 0);
        __llvm_profile_set_filename(path);
        let file = libc::fopen(path, c"w+b".as_ptr());
        assert!(!file.is_null());
        assert_eq!(__llvm_profile_set_file_object(file, 0), 0);
    }
}
