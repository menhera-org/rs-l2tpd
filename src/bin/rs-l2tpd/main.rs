//! Process integration around the embeddable service (P1–P27).
mod args;
mod caps;
mod check;
mod daemon;
mod fdstore;
mod files;
mod logger;
mod pidfile;
mod restart;
#[cfg(any(feature = "setup-systemd", test))]
mod setup;
mod signals;
mod tunable;

use args::{Args, Mode};
use rs_l2tpd::blocking::Service;
use std::io;

fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(run())
}
fn run() -> u8 {
    if let Err(error) = streams() {
        eprintln!("standard streams: {error}");
        return 1;
    }
    let original = std::env::current_dir();
    let argv: Vec<_> = std::env::args_os().collect();
    let directory = std::env::set_current_dir("/");
    let args = match Args::parse(argv.iter().skip(1).cloned()) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("{error}\n{}", args::USAGE);
            return 2;
        }
    };
    logger::init(args.verbose);
    if let Err(error) = directory {
        log::error!("chdir /: {error}");
        return 1;
    }
    match args.mode {
        Mode::AdoptVersion => {
            print!("{}", restart::VERSION);
            return 0;
        }
        Mode::Version => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            return 0;
        }
        Mode::Check => return check::run(&args.config, &args.config_dir),
        Mode::Restart => {
            return match restart::signal(&args.pid_file) {
                Ok(()) => 0,
                Err(error) => {
                    log::error!("restart request: {error}");
                    1
                }
            };
        }
        Mode::Setup => {
            #[cfg(feature = "setup-systemd")]
            return match restart::executable_at(&argv[0], original) {
                Ok(executable) => setup::run(args.prefix.as_deref(), &executable),
                Err(error) => {
                    log::error!("running executable: {error}");
                    1
                }
            };
            #[cfg(not(feature = "setup-systemd"))]
            return 2;
        }
        _ => (),
    }
    let mut pid = None;
    let mut completed = false;
    let mut result = (|| -> io::Result<u8> {
        let entry = restart::entry()?;
        pid = entry.pid;
        let inherited = fdstore::inherit()?;
        let executable = restart::executable_at(&argv[0], original)?;
        let loaded = files::load(&args.config, &args.config_dir);
        let (config, problems) = loaded.partial.into_config_lenient();
        files::report(&config, &problems, false);
        files::report_errors(&loaded.errors);
        let mut pipe = match daemon::start(args.mode == Mode::Foreground || entry.reexec)? {
            daemon::Started::Parent(code) => return Ok(code),
            daemon::Started::Child(pipe) => pipe,
        };
        let signals = signals::Signals::install()?;
        caps::report();
        let store = inherited
            .notify
            .as_deref()
            .and_then(|path| match fdstore::Store::new(path) {
                Ok(store) => Some(store),
                Err(error) => {
                    log::error!(
                        "descriptor store unavailable: {error}; continuing without a store"
                    );
                    None
                }
            });
        let capacity = if store.is_some() {
            inherited.capacity
        } else {
            0
        };
        let mut adopted = inherited.sockets;
        let mut reported = false;
        let mut service = loop {
            if signals.stopping() {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                for socket in &adopted {
                    if let Some(store) = &store
                        && let Err(error) = store.forget(socket.name(), deadline)
                    {
                        log::error!("startup withdrawal {}: {error}", socket.name());
                    }
                }
                if !adopted.is_empty() {
                    log::error!("kernel unavailable; cannot confirm inherited tunnel absence");
                }
                return Ok(1);
            }
            match Service::new(config.clone(), adopted) {
                Ok(service) => break service,
                Err((error, returned)) => {
                    adopted = returned;
                    if !reported {
                        log::error!("opening kernel interfaces: {error}; retrying");
                        reported = true;
                    }
                    signals.retry();
                }
            }
        };
        if reported {
            log::info!("kernel interfaces available");
        }
        signals.attach(service.control());
        service
            .set_store_capacity(capacity)
            .map_err(io::Error::other)?;
        let requests = service
            .take_requests()
            .map_err(io::Error::other)?
            .ok_or_else(|| io::Error::other("host receiver unavailable"))?;
        let host = fdstore::worker(requests, service.control(), store)?;
        let convergence = service.converge();
        if convergence.is_ok() && !signals.stopping() {
            // The parent may send SIGHUP as soon as readiness is announced.
            signals.ready();
            if !entry.reexec {
                if args.mode == Mode::Daemon {
                    match pidfile::PidFile::publish(&args.pid_file) {
                        Ok(published) => pid = Some(published),
                        Err(error) => log::error!(
                            "PID file {}: {error}; readiness still valid",
                            args.pid_file.display()
                        ),
                    }
                }
                daemon::ready(&mut pipe);
                log::info!("ready pid={}", std::process::id());
            }
            if entry.reexec {
                log::info!("re-exec resumed");
            }
        } else {
            service.control().shutdown();
        }
        let restart_pid = pid.clone();
        let main = args.config.clone();
        let dropins = args.config_dir.clone();
        let arguments = argv.into_iter().skip(1).collect::<Vec<_>>();
        let result = service.run(
            move |previous| files::reload(&main, &dropins, previous),
            move |sockets| {
                restart::exec(&executable, &arguments, sockets, restart_pid.as_ref())
                    .map_err(Into::into)
            },
        );
        let mut code = match convergence.and(result) {
            Ok(()) => 0,
            Err(rs_l2tpd::Error::ReloadPanicked | rs_l2tpd::Error::RestartPanicked) => 2,
            Err(error) => {
                log::error!("service: {error}");
                1
            }
        };
        drop(service);
        if host.join().is_err() {
            log::error!("host integration thread panicked");
            code = 1;
        }
        completed = true;
        Ok(code)
    })();
    if let Some(pid) = pid.as_ref()
        && let Err(error) = pid.remove()
    {
        log::error!("PID file cleanup: {error}");
        if matches!(result, Ok(0)) {
            result = Ok(1);
        }
    }
    if completed {
        log::info!("shutdown complete");
    }
    match result {
        Ok(code) => code,
        Err(error) => {
            log::error!("{error}");
            1
        }
    }
}

#[cfg(test)]
mod testdir {
    use std::path::{Path, PathBuf};
    pub struct Dir(PathBuf);
    impl Dir {
        pub fn new() -> Self {
            let mut bytes = [0; 8];
            getrandom::fill(&mut bytes).unwrap();
            let path = std::env::temp_dir()
                .join(format!("rs-l2tpd-test-{:016x}", u64::from_ne_bytes(bytes)));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

// kernel: fs/fcntl.c f_getfd, fs/file.c do_dup2, fs/open.c do_sys_openat2 (P2).
fn streams() -> io::Result<()> {
    for fd in 0..=2 {
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0 {
            continue;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EBADF) {
            return Err(error);
        }
        let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
        if null < 0 {
            return Err(io::Error::last_os_error());
        }
        if null != fd {
            let result = unsafe { libc::dup2(null, fd) };
            let error = io::Error::last_os_error();
            unsafe {
                libc::close(null);
            }
            if result < 0 {
                return Err(error);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod stream_tests {
    /// spec: P2 O1
    #[test]
    fn closed_streams_child() {
        if std::env::var_os("COMPLETION_CLOSED_STREAMS").is_none() {
            return;
        }
        for fd in 0..=2 {
            unsafe {
                libc::close(fd);
            }
        }
        super::streams().unwrap();
        for fd in 0..=2 {
            assert!(unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0);
        }
        use std::os::fd::AsRawFd;
        assert!(std::fs::File::open("/dev/null").unwrap().as_raw_fd() >= 3);
    }
    /// spec: P2 O1
    #[test]
    fn sockets_cannot_take_the_place_of_closed_standard_streams() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "stream_tests::closed_streams_child"])
            .env("COMPLETION_CLOSED_STREAMS", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }
}
