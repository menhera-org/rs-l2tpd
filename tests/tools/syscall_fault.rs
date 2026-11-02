use nix::libc;

#[allow(
    dead_code,
    reason = "shared helper; not every test binary denies duplication"
)]
pub(crate) fn refuse_dup2(errno: i32) {
    #[cfg(coverage_nightly)]
    keep_profile_output();
    on_exec_dup2(errno)().unwrap();
}

#[allow(
    dead_code,
    reason = "shared helper; only process fixtures deny dup2 on exec"
)]
pub(crate) fn on_exec_dup2(
    errno: i32,
) -> impl FnMut() -> std::io::Result<()> + Send + Sync + 'static {
    on_exec(DUP_SYSCALLS, errno)
}

pub(crate) const DUP_SYSCALLS: &[libc::c_long] = &[
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
// Syscall numbers use this target's ABI; exec hooks retain only prepared data.
pub(crate) fn refuse(syscalls: &[libc::c_long], errno: i32) {
    #[cfg(coverage_nightly)]
    keep_profile_output();
    on_exec(syscalls, errno)().unwrap();
}

/// Builds the filter now; the returned exec hook only issues raw syscalls.
pub(crate) fn on_exec(
    syscalls: &[libc::c_long],
    errno: i32,
) -> impl FnMut() -> std::io::Result<()> + Send + Sync + 'static {
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
    install(filter)
}

/// Refuses only the daemon's first standard-stream probe, preserving profile I/O.
#[allow(
    dead_code,
    reason = "shared helper; only process fixtures deny the stdin probe"
)]
pub(crate) fn on_exec_stdin_probe(
    errno: i32,
) -> impl FnMut() -> std::io::Result<()> + Send + Sync + 'static {
    let low_word = if cfg!(target_endian = "little") { 0 } else { 4 };
    let filter = [
        (0x20, 0, 0, 0),
        (0x15, 0, 5, libc::SYS_fcntl.try_into().unwrap()),
        (0x20, 0, 0, 16 + low_word),
        (0x15, 0, 3, 0),
        (0x20, 0, 0, 24 + low_word),
        (0x15, 0, 1, libc::F_GETFD.try_into().unwrap()),
        (0x06, 0, 0, 0x00050000 | u32::try_from(errno).unwrap()),
        (0x06, 0, 0, 0x7fff0000),
    ]
    .into_iter()
    .map(|(code, jt, jf, k)| libc::sock_filter { code, jt, jf, k })
    .collect();
    install(filter)
}

fn install(
    mut filter: Vec<libc::sock_filter>,
) -> impl FnMut() -> std::io::Result<()> + Send + Sync + 'static {
    let length = filter.len().try_into().unwrap();
    // TSYNC also covers an already-started dispatcher in this subprocess.
    // The kernel copies the filter while its allocation is still alive.
    move || unsafe {
        let program = libc::sock_fprog {
            len: length,
            filter: filter.as_mut_ptr(),
        };
        if libc::prctl(
            libc::PR_SET_NO_NEW_PRIVS,
            1 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            &program as *const _,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Refuses one socket option while preserving unrelated socket setup and sends.
#[allow(
    dead_code,
    reason = "shared helper; only resolver fixtures deny RA filters"
)]
pub(crate) fn on_exec_socket_option(
    level: i32,
    option: i32,
    errno: i32,
) -> impl FnMut() -> std::io::Result<()> + Send + Sync + 'static {
    let low_word = if cfg!(target_endian = "little") { 0 } else { 4 };
    let filter = [
        (0x20, 0, 0, 0),
        (0x15, 0, 5, libc::SYS_setsockopt.try_into().unwrap()),
        (0x20, 0, 0, 24 + low_word),
        (0x15, 0, 3, level.try_into().unwrap()),
        (0x20, 0, 0, 32 + low_word),
        (0x15, 0, 1, option.try_into().unwrap()),
        (0x06, 0, 0, 0x00050000 | u32::try_from(errno).unwrap()),
        (0x06, 0, 0, 0x7fff0000),
    ]
    .into_iter()
    .map(|(code, jt, jf, k)| libc::sock_filter { code, jt, jf, k })
    .collect();
    install(filter)
}

/// Matches one integer syscall argument without interfering with unrelated calls.
#[allow(
    dead_code,
    reason = "shared helper; only restart fixtures match one argument"
)]
pub(crate) fn on_exec_argument(
    syscall: libc::c_long,
    argument: u32,
    value: u32,
    errno: i32,
) -> impl FnMut() -> std::io::Result<()> + Send + Sync + 'static {
    assert!(argument < 6);
    let low_word = if cfg!(target_endian = "little") { 0 } else { 4 };
    let filter = [
        (0x20, 0, 0, 0),
        (0x15, 0, 3, syscall.try_into().unwrap()),
        (0x20, 0, 0, 16 + argument * 8 + low_word),
        (0x15, 0, 1, value),
        (0x06, 0, 0, 0x00050000 | u32::try_from(errno).unwrap()),
        (0x06, 0, 0, 0x7fff0000),
    ]
    .into_iter()
    .map(|(code, jt, jf, k)| libc::sock_filter { code, jt, jf, k })
    .collect();
    install(filter)
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

// Test-only capability reduction: include/uapi/linux/capability.h and kernel/capability.c capget/capset.
#[allow(
    dead_code,
    reason = "shared helper; only capability fixtures remove CAP_NET_ADMIN"
)]
pub(crate) fn drop_net_admin() -> bool {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Caps {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let mut header = Header {
        version: 0x20080522,
        pid: 0,
    };
    let mut caps = [Caps::default(); 2];
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_capget, &mut header, caps.as_mut_ptr()) },
        0
    );
    let held = caps[0].effective & (1 << 12) != 0;
    caps[0].effective &= !(1 << 12);
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_capset, &header, caps.as_ptr()) },
        0
    );
    held
}

#[allow(
    dead_code,
    reason = "shared helper; only warning assertions need a logger"
)]
pub(crate) fn log_warnings() {
    struct Logger;
    impl log::Log for Logger {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }
        fn log(&self, record: &log::Record<'_>) {
            eprintln!("{}", record.args());
        }
        fn flush(&self) {}
    }
    static LOGGER: Logger = Logger;
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(log::LevelFilter::Warn);
}
