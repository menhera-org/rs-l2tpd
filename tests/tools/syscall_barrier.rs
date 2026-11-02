//! Stops only a disposable test worker at syscall entry; no daemon hook is added.
use nix::errno::Errno;
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use std::fs::OpenOptions;
use std::io::{self, Read, Seek};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const READY: &str = "RS_L2TPD_SYSCALL_BARRIER_TID";

// kernel: include/uapi/linux/ptrace.h; kernel/ptrace.c ptrace_request.
fn trace(request: i64, tid: i32, address: usize, data: usize) -> io::Result<libc::c_long> {
    Errno::clear();
    let value = unsafe {
        libc::ptrace(
            request as _,
            tid,
            address as *mut libc::c_void,
            data as *mut libc::c_void,
        )
    };
    let error = Errno::last();
    if value == -1 && error != Errno::UnknownErrno {
        Err(error.into())
    } else {
        Ok(value)
    }
}

/// Called in the fresh child's test worker, before the operation under test.
pub(crate) fn stop() -> io::Result<()> {
    let path =
        std::env::var_os(READY).ok_or_else(|| io::Error::other("missing syscall barrier path"))?;
    // Defer signal-delivery stops until the TID is published and SIGSTOP has armed the tracer.
    let blocked = nix::sys::signal::SigSet::all();
    let mut previous = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    // nix 0.30.1 misreads positive pthread errors; these calls return the error number.
    let status =
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, blocked.as_ref(), &mut previous) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    let result = (|| {
        trace(i64::from(libc::PTRACE_TRACEME), 0, 0, 0)?;
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        std::fs::write(path, tid.to_string())?;
        if unsafe { libc::raise(libc::SIGSTOP) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })();
    let restored =
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut()) };
    result?;
    if restored != 0 {
        return Err(io::Error::from_raw_os_error(restored));
    }
    Ok(())
}

// kernel: include/uapi/linux/ptrace.h struct ptrace_syscall_info (all required kernels).
// nix 0.30.1 passes a zero buffer size and assumes initialization; musl lacks its API.
#[derive(Default)]
#[repr(C)]
struct Info {
    op: u8,
    reserved: [u8; 3],
    arch: u32,
    instruction: u64,
    stack: u64,
    data: [u64; 8],
}

fn entry(tid: i32) -> io::Result<Option<(u64, [u64; 6])>> {
    let mut info = Info::default();
    // kernel: kernel/ptrace.c ptrace_get_syscall_info copies min(user_size, actual_size).
    let copied = trace(
        0x420e,
        tid,
        size_of::<Info>(),
        &mut info as *mut Info as usize,
    )?;
    if info.op != 1 {
        return Ok(None);
    }
    if copied < 80 {
        return Err(io::Error::other("incomplete syscall-entry information"));
    }
    Ok(Some((
        info.data[0],
        std::array::from_fn(|index| info.data[index + 1]),
    )))
}

/// Reads a bounded pathname from the stopped worker, checking errno on PEEKDATA.
pub(crate) fn path(tid: i32, address: u64) -> io::Result<Vec<u8>> {
    let address =
        usize::try_from(address).map_err(|_| io::Error::other("invalid traced pointer"))?;
    let mut bytes = Vec::new();
    for offset in (0..4096).step_by(size_of::<libc::c_long>()) {
        let pointer = address
            .checked_add(offset)
            .ok_or_else(|| io::Error::other("invalid traced pointer"))?;
        let word = trace(i64::from(libc::PTRACE_PEEKDATA), tid, pointer, 0)?;
        for byte in word.to_ne_bytes() {
            if byte == 0 {
                return Ok(bytes);
            }
            bytes.push(byte);
        }
    }
    Err(io::Error::other("unterminated traced pathname"))
}

struct Running {
    child: Child,
    tid: Option<i32>,
}
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        if let Some(tid) = self.tid {
            let _ = waitpid(Pid::from_raw(tid), Some(WaitPidFlag::__WALL));
        }
        let _ = self.child.wait();
    }
}

/// Drives the child's explicitly traced worker; other children/threads are untouched.
pub(crate) fn run(
    command: &mut Command,
    directory: &Path,
    mut at_entry: impl FnMut(i32, u64, [u64; 6]) -> io::Result<()>,
) -> io::Result<Output> {
    let ready = directory.join("trace-tid");
    let mut output = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(directory.join("trace-output"))?;
    let mut child = Running {
        child: command
            .env(READY, &ready)
            .stdout(Stdio::from(output.try_clone()?))
            .stderr(Stdio::from(output.try_clone()?))
            .spawn()?,
        tid: None,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let tid = loop {
        if let Ok(text) = std::fs::read_to_string(&ready)
            && let Ok(tid) = text.parse::<i32>()
        {
            break tid;
        }
        if child.child.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err(io::Error::other(
                "test worker did not reach its syscall barrier",
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    child.tid = Some(tid);
    let mut started = false;
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "traced test worker",
            ));
        }
        match waitpid(
            Pid::from_raw(tid),
            Some(WaitPidFlag::__WALL | WaitPidFlag::WNOHANG),
        )? {
            WaitStatus::Stopped(_, nix::sys::signal::Signal::SIGSTOP) if !started => {
                trace(
                    i64::from(libc::PTRACE_SETOPTIONS),
                    tid,
                    0,
                    libc::PTRACE_O_TRACESYSGOOD as usize,
                )?;
                started = true;
                trace(i64::from(libc::PTRACE_SYSCALL), tid, 0, 0)?;
            }
            WaitStatus::PtraceSyscall(_) => {
                if let Some((number, arguments)) = entry(tid)? {
                    at_entry(tid, number, arguments)?;
                }
                trace(i64::from(libc::PTRACE_SYSCALL), tid, 0, 0)?;
            }
            WaitStatus::Stopped(_, signal)
                if started && signal != nix::sys::signal::Signal::SIGSTOP =>
            {
                // Signal-delivery stops must preserve the worker's actual signal delivery.
                trace(i64::from(libc::PTRACE_SYSCALL), tid, 0, signal as usize)?;
            }
            WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _) => {
                child.tid = None;
                break;
            }
            WaitStatus::StillAlive => std::thread::sleep(Duration::from_millis(1)),
            status => {
                return Err(io::Error::other(format!(
                    "unexpected trace stop: {status:?}"
                )));
            }
        }
    }
    let status = loop {
        if let Some(status) = child.child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "traced test process",
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    output.rewind()?;
    let mut bytes = Vec::new();
    output.read_to_end(&mut bytes)?;
    Ok(Output {
        status,
        stdout: bytes,
        stderr: Vec::new(),
    })
}

/// spec: P10, P11, C3, C4
#[test]
fn query_sizes_peek_errors_and_callback_cleanup_are_checked() {
    const CHILD: &str = "RS_L2TPD_BARRIER_CONTRACT_CHILD";
    if std::env::var_os(CHILD).is_some() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static DELIVERED: AtomicUsize = AtomicUsize::new(0);
        extern "C" fn delivered(signal: i32) {
            DELIVERED.fetch_or(
                if signal == libc::SIGUSR1 { 1 } else { 2 },
                Ordering::Relaxed,
            );
        }
        for signal in [libc::SIGUSR1, libc::SIGCHLD] {
            assert_ne!(
                unsafe { libc::signal(signal, delivered as *const () as libc::sighandler_t) },
                libc::SIG_ERR
            );
        }
        let mut expected = nix::sys::signal::SigSet::thread_get_mask().unwrap();
        expected.add(nix::sys::signal::Signal::SIGWINCH);
        expected.thread_set_mask().unwrap();
        stop().unwrap();
        let restored = nix::sys::signal::SigSet::thread_get_mask().unwrap();
        for signal in nix::sys::signal::Signal::iterator() {
            assert_eq!(restored.contains(signal), expected.contains(signal));
        }
        for signal in [libc::SIGUSR1, libc::SIGCHLD] {
            assert_eq!(unsafe { libc::raise(signal) }, 0);
        }
        assert_eq!(DELIVERED.load(Ordering::Relaxed), 3);
        println!("PTRACE_SIGNAL_DELIVERY_CHECKED=3");
        let mut bytes = [0xff_u8; 4096];
        bytes[size_of::<libc::c_long>()] = 0;
        assert_eq!(
            unsafe { libc::write(-1, bytes.as_ptr().cast(), bytes.len()) },
            -1
        );
        bytes.fill(0xff);
        assert_eq!(
            unsafe { libc::write(-2, bytes.as_ptr().cast(), bytes.len()) },
            -1
        );
        return;
    }
    #[cfg(target_env = "gnu")]
    assert_eq!(size_of::<Info>(), size_of::<libc::ptrace_syscall_info>());
    for fail_callback in [false, true] {
        let dir = crate::testdir::Dir::new();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "syscall_barrier::query_sizes_peek_errors_and_callback_cleanup_are_checked",
                "--nocapture",
            ])
            .env(CHILD, "1");
        let mut checked = 0;
        let result = run(&mut command, dir.path(), |tid, number, arguments| {
            if number != libc::SYS_write as u64 || ![-1_i32, -2].contains(&(arguments[0] as i32)) {
                return Ok(());
            }
            checked += 1;
            println!(
                "PTRACE_FD_ARGUMENT raw={} value={}",
                arguments[0], arguments[0] as i32
            );
            if fail_callback {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            if arguments[0] as i32 == -1 {
                let mut untouched = [0xa5_u8; size_of::<Info>()];
                let required = trace(0x420e, tid, 0, untouched.as_mut_ptr() as usize)?;
                assert!(required >= 80);
                assert!(
                    untouched.iter().all(|byte| *byte == 0xa5),
                    "zero size must copy no output"
                );
                assert_eq!(
                    path(tid, arguments[1])?,
                    vec![0xff; size_of::<libc::c_long>()]
                );
                assert_eq!(path(tid, 0).unwrap_err().raw_os_error(), Some(libc::EIO));
                assert_eq!(
                    trace(i64::from(u32::MAX), tid, 0, 0)
                        .unwrap_err()
                        .raw_os_error(),
                    Some(libc::EIO)
                );
            } else {
                assert!(
                    path(tid, arguments[1])
                        .unwrap_err()
                        .to_string()
                        .contains("unterminated")
                );
            }
            Ok(())
        });
        if fail_callback {
            assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EIO));
            let tid = std::fs::read_to_string(dir.path().join("trace-tid"))
                .unwrap()
                .parse::<i32>()
                .unwrap();
            assert_eq!(
                waitpid(
                    Pid::from_raw(tid),
                    Some(WaitPidFlag::__WALL | WaitPidFlag::WNOHANG)
                ),
                Err(Errno::ECHILD)
            );
            assert_eq!(checked, 1);
        } else {
            let output = result.unwrap();
            assert!(output.status.success(), "{output:?}");
            assert_eq!(checked, 2);
            assert!(
                String::from_utf8_lossy(&output.stdout)
                    .contains("PTRACE_SIGNAL_DELIVERY_CHECKED=3")
            );
        }
    }
}

/// spec: P4, P12
#[test]
fn a_refused_arming_mask_returns_the_pthread_error_before_tracing() {
    const CHILD: &str = "PHASE6_BARRIER_MASK_REFUSAL";
    if std::env::var_os(CHILD).is_some() {
        #[cfg(coverage_nightly)]
        crate::syscall_fault::keep_profile_output();
        crate::syscall_fault::refuse(&[libc::SYS_rt_sigprocmask], libc::EIO);
        assert_eq!(stop().unwrap_err().raw_os_error(), Some(libc::EIO));
        println!("TRACER_ARMING_MASK_REFUSAL_CHECKED=1");
        return;
    }
    let dir = crate::testdir::Dir::new();
    let ready = dir.path().join("ready");
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "syscall_barrier::a_refused_arming_mask_returns_the_pthread_error_before_tracing",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env(READY, &ready)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(!ready.exists());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("TRACER_ARMING_MASK_REFUSAL_CHECKED=1")
    );
}
