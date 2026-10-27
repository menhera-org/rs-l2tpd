//! The `rs-l2tpd` daemon: command line, configuration files, logging,
//! signals, daemonisation and the optional installer around the
//! `rs_l2tpd` library.

use clap::{ArgAction, Parser};
use log::{error, info, warn};
use rs_l2tpd::config::{Config, EntryKind, PartialConfig, ProblemEffect};
use rs_l2tpd::service::{Control, Service, Startup};
use rs_l2tpd::{Error, Result};

use std::fs;
use std::path::{Path, PathBuf};
#[cfg(feature = "setup")]
use std::process::Command;

/// This is the path to the main configuration file.
const CONFIG_FILE_PATH: &str = env!("CONFIG_FILE_PATH");

/// This is where configuration overrides (filenames ending in .toml) live.
const CONFIG_DIR_PATH: &str = env!("CONFIG_DIR_PATH");

#[cfg(feature = "setup")]
const INSTALL_BINARY_PATH: &str = "/usr/local/bin/rs-l2tpd";
#[cfg(feature = "setup")]
const INSTALL_SYSTEMD_UNIT_PATH: &str = "/usr/local/lib/systemd/system/rs-l2tpd.service";
const DEFAULT_PIDFILE_PATH: &str = "/run/rs-l2tpd.pid";

#[derive(Debug, Parser)]
#[command(version, disable_help_flag = false, disable_version_flag = false)]
struct Args {
    /// Increase log verbosity.
    #[arg(short, long, action = ArgAction::SetTrue)]
    verbose: bool,

    /// Validate the merged configuration, print what would be applied and
    /// exit; the exit status is 1 if any problem was found.
    #[arg(short = 'c', long, action = ArgAction::SetTrue)]
    check: bool,

    /// Write the daemon PID to this file after initial readiness.
    #[arg(short = 'p', long, default_value = DEFAULT_PIDFILE_PATH)]
    pidfile: PathBuf,

    /// Install this binary and a systemd unit under /usr/local and enable the service.
    #[cfg(feature = "setup")]
    #[arg(long, action = ArgAction::SetTrue)]
    setup: bool,
}

mod unix_daemon {
    use rs_l2tpd::{Error, Result};

    use std::collections::VecDeque;
    use std::ffi::{CString, OsString};
    use std::fs;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    const READY: u8 = b'R';
    const FAILED: u8 = b'F';

    pub(crate) struct ReadinessNotifier {
        fd: Option<libc::c_int>,
    }

    impl ReadinessNotifier {
        fn new(fd: libc::c_int) -> Self {
            Self { fd: Some(fd) }
        }

        pub(crate) fn signal_ready(&mut self) -> Result<()> {
            self.write_message(READY)
        }

        pub(crate) fn signal_failure(&mut self) {
            let _ = self.write_message(FAILED);
        }

        fn write_message(&mut self, message: u8) -> Result<()> {
            let Some(fd) = self.fd.take() else {
                return Ok(());
            };
            let buf = [message];
            let result = loop {
                // SAFETY: fd is owned by this notifier and buf points to one valid byte.
                let written = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
                if written == 1 {
                    break Ok(());
                }
                if written < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    break Err(Error::Other(format!(
                        "failed to notify startup parent: {e}"
                    )));
                }
                break Err(Error::Other(
                    "failed to notify startup parent: short write".to_string(),
                ));
            };
            close_fd(fd);
            result
        }
    }

    impl Drop for ReadinessNotifier {
        fn drop(&mut self) {
            if let Some(fd) = self.fd.take() {
                close_fd(fd);
            }
        }
    }

    pub(crate) fn daemonize() -> Result<ReadinessNotifier> {
        let mut pipe_fds = [0 as libc::c_int; 2];
        // SAFETY: pipe_fds points to two valid c_int slots.
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
            return Err(Error::Other(format!(
                "failed to create readiness pipe: {}",
                io::Error::last_os_error()
            )));
        }

        // SAFETY: fork is called before the Tokio runtime is created.
        match unsafe { libc::fork() } {
            -1 => {
                close_fd(pipe_fds[0]);
                close_fd(pipe_fds[1]);
                Err(Error::Other(format!(
                    "first fork failed: {}",
                    io::Error::last_os_error()
                )))
            }
            0 => {
                close_fd(pipe_fds[0]);
                // SAFETY: setsid has no Rust-side invariants.
                if unsafe { libc::setsid() } < 0 {
                    signal_failure_and_exit(pipe_fds[1]);
                }

                // SAFETY: second fork is still before the Tokio runtime is created.
                match unsafe { libc::fork() } {
                    -1 => signal_failure_and_exit(pipe_fds[1]),
                    0 => {
                        // The daemon creates only its PID file and that
                        // file's directory, with explicit modes; a
                        // restrictive umask is a second line of defence
                        // against world-writable files.
                        // SAFETY: setting a process umask has no Rust-side invariants.
                        unsafe {
                            libc::umask(0o022);
                        }
                        Ok(ReadinessNotifier::new(pipe_fds[1]))
                    }
                    _pid => {
                        // SAFETY: the intermediate child must not continue Rust control flow.
                        unsafe { libc::_exit(0) };
                    }
                }
            }
            _pid => {
                close_fd(pipe_fds[1]);
                let status = wait_for_readiness(pipe_fds[0]);
                close_fd(pipe_fds[0]);
                std::process::exit(status);
            }
        }
    }

    #[cfg(feature = "setup")]
    pub(crate) fn effective_uid() -> u32 {
        // SAFETY: geteuid has no safety preconditions.
        unsafe { libc::geteuid() as u32 }
    }

    /// Publishes a fresh PID-file inode when its directory is writable.
    /// Otherwise, a precreated owned file may be updated only after checking
    /// its identity and restrictive permissions. Legacy writable inodes are
    /// always replaced, so their old descriptors cannot alter the new PID.
    pub(crate) fn write_pid_file(path: &Path) -> Result<()> {
        write_pid_file_inner(path)
            .map_err(|e| Error::Other(format!("failed to write pidfile {}: {e}", path.display())))
    }

    fn path_component(name: &std::ffi::OsStr) -> io::Result<CString> {
        CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
    }

    fn inspect_at(parent: &fs::File, name: &CString) -> io::Result<Option<libc::stat>> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: the parent descriptor and NUL-terminated name are valid,
        // and stat points to writable storage of the required size.
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
        {
            // SAFETY: fstatat initialized stat on success.
            return Ok(Some(unsafe { stat.assume_init() }));
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(error)
        }
    }

    fn trusted_owner(owner: libc::uid_t, uid: libc::uid_t) -> bool {
        owner == 0 || owner == uid
    }

    fn secure_pid_directory(directory: &fs::File, uid: libc::uid_t) -> io::Result<()> {
        let metadata = directory.metadata()?;
        if !trusted_owner(metadata.uid(), uid) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "pidfile directory is owned by another user",
            ));
        }
        let mode = metadata.mode();
        // A directory other users can write to lets them replace the PID
        // file; sticky directories protect our entries. The daemon does not
        // change the permissions of directories it did not create: that
        // would silently alter an administrator's setup, and refusing would
        // break deployments that worked before. It warns instead; the PID
        // file is normally published as a fresh inode owned by the daemon
        // user; the guarded precreated-file fallback checks this mode too.
        if mode & 0o022 != 0 && mode & libc::S_ISVTX == 0 {
            log::warn!(
                "pidfile directory is writable by other users (mode {:04o}); the PID file can be replaced by them",
                mode & 0o7777
            );
        }
        Ok(())
    }

    fn directory_components(path: &Path) -> VecDeque<OsString> {
        path.components()
            .map(|component| component.as_os_str().to_owned())
            .collect()
    }

    fn open_pid_root() -> io::Result<fs::File> {
        // SAFETY: the static pathname is NUL-terminated. O_PATH obtains a
        // directory handle without requiring permission to list its entries.
        let fd = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: open returned a new owned descriptor.
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }

    fn read_link_at(parent: &fs::File, name: &CString) -> io::Result<PathBuf> {
        let mut buffer = vec![0_u8; 256];
        loop {
            // SAFETY: the descriptor and name are valid and buffer points
            // to buffer.len() writable bytes. readlinkat adds no NUL.
            let size = unsafe {
                libc::readlinkat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if size < 0 {
                return Err(io::Error::last_os_error());
            }
            if (size as usize) < buffer.len() {
                buffer.truncate(size as usize);
                return Ok(PathBuf::from(OsString::from_vec(buffer)));
            }
            if buffer.len() >= 65536 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "symlink too long",
                ));
            }
            buffer.resize(buffer.len() * 2, 0);
        }
    }

    fn open_pid_directory(path: &Path, uid: libc::uid_t) -> io::Result<fs::File> {
        let absolute = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()?.join(path)
        };
        let mut pending = directory_components(&absolute);
        let mut directory = open_pid_root()?;
        secure_pid_directory(&directory, uid)?;
        let mut symlinks = 0;
        while let Some(component) = pending.pop_front() {
            if component == "/" {
                directory = open_pid_root()?;
                secure_pid_directory(&directory, uid)?;
                continue;
            }
            let name = path_component(&component)?;
            loop {
                // SAFETY: both descriptor and NUL-terminated name are
                // valid. O_NOFOLLOW keeps inspection tied to this entry.
                let fd = unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd >= 0 {
                    // SAFETY: openat returned a new owned descriptor.
                    let next = unsafe { fs::File::from_raw_fd(fd) };
                    secure_pid_directory(&next, uid)?;
                    directory = next;
                    break;
                }
                let open_error = io::Error::last_os_error();
                match inspect_at(&directory, &name)? {
                    None => {
                        // SAFETY: the secured parent descriptor and name
                        // are valid; newly created directories are private
                        // to their owner for modifications.
                        if unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o755) }
                            != 0
                            && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
                        {
                            return Err(io::Error::last_os_error());
                        }
                    }
                    Some(stat) if stat.st_mode & libc::S_IFMT == libc::S_IFLNK => {
                        if !trusted_owner(stat.st_uid, uid) || symlinks >= 40 {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "untrusted or looping pidfile directory symlink",
                            ));
                        }
                        symlinks += 1;
                        let target = read_link_at(&directory, &name)?;
                        for component in directory_components(&target).into_iter().rev() {
                            pending.push_front(component);
                        }
                        break;
                    }
                    Some(_) => return Err(open_error),
                }
            }
        }
        Ok(directory)
    }

    fn validate_pid_entry(stat: &libc::stat, uid: libc::uid_t) -> io::Result<()> {
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_uid != uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "existing pidfile must be a regular file owned by the daemon user",
            ));
        }
        Ok(())
    }

    fn update_precreated_pid_file(
        directory: &fs::File,
        name: &CString,
        expected: Option<&libc::stat>,
        uid: libc::uid_t,
        pid: u32,
    ) -> io::Result<()> {
        use std::io::Write;

        let unsafe_file = || {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "non-writable pidfile directory requires an unchanged, owned regular file with one link and no group/other write permission",
            )
        };
        let expected = expected.ok_or_else(unsafe_file)?;
        validate_pid_entry(expected, uid)?;
        if expected.st_nlink != 1 || expected.st_mode & 0o022 != 0 {
            return Err(unsafe_file());
        }
        let parent = directory.metadata()?;
        if parent.mode() & 0o022 != 0 && parent.mode() & libc::S_ISVTX == 0 {
            return Err(unsafe_file());
        }

        // SAFETY: the descriptor and name are valid. Do not truncate until
        // fstat confirms this is the previously inspected, safe inode.
        // O_NONBLOCK also prevents a raced-in FIFO from hanging startup.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a new owned descriptor.
        let mut file = unsafe { fs::File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.dev() != expected.st_dev
            || metadata.ino() != expected.st_ino
            || metadata.nlink() != 1
            || metadata.mode() & 0o022 != 0
        {
            return Err(unsafe_file());
        }
        // POSIX ACL write grants are limited by the group-class mask,
        // reflected in these mode bits. Preserve the existing safe mode.
        file.set_len(0)?;
        file.write_all(format!("{pid}\n").as_bytes())?;
        file.sync_all()
    }

    fn write_pid_file_inner(path: &Path) -> io::Result<()> {
        use std::io::Write;
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

        let name = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "pidfile path has no filename")
        })?;
        let name = path_component(name)?;
        // SAFETY: geteuid has no safety preconditions.
        let uid = unsafe { libc::geteuid() };
        let directory = open_pid_directory(path.parent().unwrap_or(Path::new(".")), uid)?;
        let existing = inspect_at(&directory, &name)?;
        if let Some(stat) = &existing {
            validate_pid_entry(stat, uid)?;
        }
        let pid = std::process::id();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temporary = (0..128)
            .find_map(|_| {
                let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
                let temporary = CString::new(format!(".rs-l2tpd-{pid}-{nonce}-{serial}.tmp"))
                    .expect("generated name contains no NUL");
                // SAFETY: the directory and name are valid. O_EXCL creates
                // a fresh inode and refuses any preexisting entry.
                let fd = unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        temporary.as_ptr(),
                        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                        0o600,
                    )
                };
                if fd >= 0 {
                    // SAFETY: openat returned a new owned descriptor.
                    Some(Ok((temporary, unsafe { fs::File::from_raw_fd(fd) })))
                } else {
                    let error = io::Error::last_os_error();
                    (error.kind() != io::ErrorKind::AlreadyExists).then_some(Err(error))
                }
            })
            .unwrap_or_else(|| Err(io::Error::other("cannot create temporary pidfile")));
        let (temporary, mut file) = match temporary {
            Ok(created) => created,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                return update_precreated_pid_file(&directory, &name, existing.as_ref(), uid, pid);
            }
            Err(error) => return Err(error),
        };
        let result = (|| {
            file.write_all(format!("{pid}\n").as_bytes())?;
            file.set_permissions(fs::Permissions::from_mode(0o644))?;
            file.sync_all()?;
            for _ in 0..128 {
                let existing = inspect_at(&directory, &name)?;
                if let Some(stat) = existing {
                    validate_pid_entry(&stat, uid)?;
                    // SAFETY: both names and their secured directory are
                    // valid. Replacing the entry never follows a symlink.
                    if unsafe {
                        libc::renameat(
                            directory.as_raw_fd(),
                            temporary.as_ptr(),
                            directory.as_raw_fd(),
                            name.as_ptr(),
                        )
                    } == 0
                    {
                        return Ok(());
                    }
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: both names and the secured directory are valid.
                // linkat publishes without overwriting an entry created
                // by another user in a sticky directory since inspection.
                if unsafe {
                    libc::linkat(
                        directory.as_raw_fd(),
                        temporary.as_ptr(),
                        directory.as_raw_fd(),
                        name.as_ptr(),
                        0,
                    )
                } == 0
                {
                    return Ok(());
                }
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(error);
                }
            }
            Err(io::Error::other(
                "pidfile changed repeatedly during publication",
            ))
        })();
        // SAFETY: this is the temporary entry created above, relative to
        // the same held directory. After renameat it no longer exists.
        unsafe { libc::unlinkat(directory.as_raw_fd(), temporary.as_ptr(), 0) };
        result
    }

    pub(crate) fn remove_pid_file(path: PathBuf) {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => log::warn!("failed to remove pidfile {}: {}", path.display(), e),
        }
    }

    fn wait_for_readiness(fd: libc::c_int) -> i32 {
        let mut buf = [0_u8; 1];
        loop {
            // SAFETY: fd is a valid read end here and buf points to one writable byte.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n == 1 {
                return if buf[0] == READY { 0 } else { 1 };
            }
            if n == 0 {
                return 1;
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return 1;
            }
        }
    }

    fn signal_failure_and_exit(fd: libc::c_int) -> ! {
        let buf = [FAILED];
        // SAFETY: fd is the readiness pipe write end and buf points to one valid byte.
        unsafe {
            let _ = libc::write(fd, buf.as_ptr().cast(), buf.len());
            let _ = libc::close(fd);
            libc::_exit(1);
        }
    }

    fn close_fd(fd: libc::c_int) {
        // SAFETY: closing an fd is safe; errors are intentionally ignored for cleanup.
        unsafe {
            let _ = libc::close(fd);
        }
    }

    #[cfg(test)]
    mod pid_security_tests {
        use super::{
            inspect_at, open_pid_directory, trusted_owner, update_precreated_pid_file,
            validate_pid_entry,
        };

        #[test]
        fn rejects_foreign_owned_pid_entries_for_root_and_capability_users() {
            // SAFETY: libc::stat consists of integer fields and padding;
            // zero is a valid initial value for every field.
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            stat.st_mode = libc::S_IFREG | 0o644;
            for uid in [0, 1000] {
                stat.st_uid = uid;
                assert!(validate_pid_entry(&stat, uid).is_ok());
                stat.st_uid = uid + 1;
                assert!(validate_pid_entry(&stat, uid).is_err());
                assert!(trusted_owner(0, uid));
                assert!(trusted_owner(uid, uid));
                assert!(!trusted_owner(uid + 1, uid));
            }
        }

        #[test]
        fn precreated_pid_fallback_checks_identity_before_truncation() {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "rs-l2tpd-pid-identity-{}-{unique}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            let pidfile = path.join("daemon.pid");
            std::fs::write(&pidfile, "original\n").unwrap();
            // SAFETY: geteuid has no safety preconditions.
            let uid = unsafe { libc::geteuid() };
            let directory = open_pid_directory(&path, uid).unwrap();
            let name = std::ffi::CString::new("daemon.pid").unwrap();
            let expected = inspect_at(&directory, &name).unwrap().unwrap();
            std::fs::rename(&pidfile, path.join("original")).unwrap();
            std::fs::write(&pidfile, "replacement\n").unwrap();

            assert!(update_precreated_pid_file(
                &directory,
                &name,
                Some(&expected),
                uid,
                std::process::id(),
            )
            .is_err());
            assert_eq!(std::fs::read_to_string(&pidfile).unwrap(), "replacement\n");
            assert_eq!(
                std::fs::read_to_string(path.join("original")).unwrap(),
                "original\n"
            );
            std::fs::remove_dir_all(path).unwrap();
        }
    }
}

/// Lists the configuration files to merge: `file` if it exists, then every
/// regular `.toml` file in `dir` in lexicographic order. A missing
/// directory is not an error.
fn list_toml_files_at(file: &Path, dir: &Path) -> Result<Vec<PathBuf>> {
    let mut dropins = Vec::new();

    match fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries {
                let path = entry
                    .map_err(|e| Error::Other(format!("failed to read directory entry: {e}")))?
                    .path();
                let is_toml = path
                    .extension()
                    .and_then(|s| s.to_str())
                    .map(|ext| ext.eq_ignore_ascii_case("toml"))
                    .unwrap_or(false);
                if path.is_file() && is_toml {
                    dropins.push(path);
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // directory does not exist -> not an error
        }
        Err(e) => {
            return Err(Error::Other(format!(
                "failed to read {}: {e}",
                dir.display()
            )))
        }
    }

    dropins.sort(); // lexicographic order among drop-ins only

    let mut files = Vec::with_capacity(dropins.len() + 1);
    if file.is_file() {
        files.push(file.to_path_buf());
    }
    files.extend(dropins);
    Ok(files)
}

fn parse_toml_config(path: &Path) -> Result<PartialConfig> {
    let text = fs::read_to_string(path)
        .map_err(|e| Error::InvalidConfig(format!("{}: {e}", path.display())))?;
    toml::from_str(&text).map_err(|e| Error::InvalidConfig(format!("{}: {e}", path.display())))
}

/// The message of a configuration error, without the generic prefix.
fn config_problem(error: &Error) -> String {
    match error {
        Error::InvalidConfig(message) => message.clone(),
        other => other.to_string(),
    }
}

/// A configuration loaded leniently: what will be applied, and the problems
/// found on the way, each naming the file or entry it concerns. `errors`
/// are what was left out: a drop-in directory that could not be listed,
/// files that could not be read or parsed and entries that failed
/// validation. `warnings` are entries kept in a degraded form: a tunnel
/// without a usable peer, a session with the kernel's hardware address.
/// Either way the result may be empty, which is a valid configuration.
struct LoadedConfig {
    config: Config,
    errors: Vec<String>,
    warnings: Vec<String>,
}

/// Reads and merges the configuration files. A drop-in directory that
/// cannot be listed and files that cannot be read or parsed are reported
/// and skipped.
fn read_partial_config(file: &Path, dir: &Path) -> (PartialConfig, Vec<String>) {
    let mut errors = Vec::new();
    let files = match list_toml_files_at(file, dir) {
        Ok(files) => files,
        Err(e) => {
            errors.push(format!(
                "{}; using {} alone",
                config_problem(&e),
                file.display()
            ));
            if file.is_file() {
                vec![file.to_path_buf()]
            } else {
                Vec::new()
            }
        }
    };
    let mut partial = PartialConfig::default();
    for path in files {
        match parse_toml_config(&path) {
            Ok(document) => partial.merge(document),
            Err(e) => errors.push(config_problem(&e)),
        }
    }
    (partial, errors)
}

/// Loads the configuration for start-up, keeping everything usable; see
/// `LoadedConfig`. A rejected tunnel takes its sessions with it.
fn load_config_lenient_at(file: &Path, dir: &Path) -> LoadedConfig {
    let (partial, mut errors) = read_partial_config(file, dir);
    let (config, problems) = partial.into_config_lenient();
    let mut warnings = Vec::new();
    for problem in problems {
        match tolerated_as(problem.effect()) {
            Some(how) => warnings.push(format!("{how}: {problem}")),
            None => errors.push(problem.to_string()),
        }
    }
    LoadedConfig {
        config,
        errors,
        warnings,
    }
}

/// How the daemon copes with a problem that does not reject its entry.
fn tolerated_as(effect: ProblemEffect) -> Option<&'static str> {
    match effect {
        ProblemEffect::NoPeer => Some("no peer until corrected"),
        ProblemEffect::KernelHwAddr => Some("kernel hardware address until corrected"),
        ProblemEffect::KeptPrevious => Some("keeping the previous values until corrected"),
        _ => None,
    }
}

/// Loads the configuration for a reload, `previous` being the one in
/// force. Mistakes degrade rather than fail and never take a running tunnel
/// or session down: an unusable endpoint or hardware address is applied as
/// at start-up, an entry that would be rejected keeps its previous values,
/// and a new entry that would be rejected is left out, each with a warning.
/// Only a file that cannot be read or parsed, whose entries cannot be told
/// apart, or an entry whose previous values no longer fit the rest keeps
/// the whole previous configuration in force, which the error says.
fn load_config_for_reload_at(file: &Path, dir: &Path, previous: &Config) -> Result<Config> {
    let (partial, file_errors) = read_partial_config(file, dir);
    if !file_errors.is_empty() {
        return Err(Error::InvalidConfig(format!(
            "{}; keeping the previous configuration",
            file_errors.join("; ")
        )));
    }
    let (config, problems) = partial.into_config_with_previous(previous);
    let mut errors = Vec::new();
    for problem in problems {
        let existed = match problem.kind() {
            EntryKind::Tunnel => previous.tunnels().contains_key(problem.name()),
            EntryKind::Session => previous.sessions().contains_key(problem.name()),
            _ => false,
        };
        match (problem.effect(), existed) {
            (ProblemEffect::Rejected, true) => errors.push(problem.to_string()),
            (ProblemEffect::Rejected, false) => {
                warn!("configuration problem, left out: {problem}");
            }
            (effect, _) => match tolerated_as(effect) {
                Some(how) => warn!("configuration problem, {how}: {problem}"),
                None => errors.push(problem.to_string()),
            },
        }
    }
    if errors.is_empty() {
        Ok(config)
    } else {
        Err(Error::InvalidConfig(format!(
            "{}; the previous values no longer fit, keeping the previous configuration",
            errors.join("; ")
        )))
    }
}

fn load_config_lenient() -> LoadedConfig {
    load_config_lenient_at(Path::new(CONFIG_FILE_PATH), Path::new(CONFIG_DIR_PATH))
}

fn load_config_for_reload(previous: &Config) -> Result<Config> {
    load_config_for_reload_at(
        Path::new(CONFIG_FILE_PATH),
        Path::new(CONFIG_DIR_PATH),
        previous,
    )
}

/// The service's reload callback: it loads against the configuration in
/// force, which the control handle reports.
fn reload_with(control: Control) -> impl FnMut() -> Result<Config> {
    move || load_config_for_reload(&control.config())
}

/// SIGHUP reloads, SIGTERM and SIGINT shut down; both drive the service
/// through its control handle.
fn install_signal_handlers(control: Control) -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut hup = signal(SignalKind::hangup())
        .map_err(|e| Error::Other(format!("failed to install SIGHUP handler: {e}")))?;
    let hup_control = control.clone();
    tokio::spawn(async move {
        while hup.recv().await.is_some() {
            info!("received SIGHUP");
            if let Err(e) = hup_control.reload_wait().await {
                warn!("service stopped before reload could be delivered: {}", e);
                break;
            }
        }
    });

    let mut term = signal(SignalKind::terminate())
        .map_err(|e| Error::Other(format!("failed to install SIGTERM handler: {e}")))?;
    let mut int = signal(SignalKind::interrupt())
        .map_err(|e| Error::Other(format!("failed to install SIGINT handler: {e}")))?;
    tokio::spawn(async move {
        tokio::select! {
            _ = term.recv() => info!("received SIGTERM"),
            _ = int.recv() => info!("received SIGINT"),
        }
        if let Err(e) = control.shutdown() {
            warn!("shutdown request dropped: {}", e);
        }
    });

    Ok(())
}

#[cfg(feature = "setup")]
fn ensure_root_uid() -> Result<()> {
    if unix_daemon::effective_uid() != 0 {
        return Err(Error::Other(
            "--setup requires root privileges (expected effective UID 0)".to_string(),
        ));
    }
    Ok(())
}

#[cfg(feature = "setup")]
fn create_empty_file(path: &Path) -> Result<()> {
    if path.is_file() {
        return Ok(());
    }
    if path.exists() {
        return Err(Error::Other(format!(
            "expected file path is not a regular file: {}",
            path.display()
        )));
    }
    std::fs::File::create(path)
        .map(|_| ())
        .map_err(|e| Error::Other(format!("failed to create {}: {e}", path.display())))
}

/// Copies `source` to `destination` through a temporary file next to it
/// and an atomic rename, so that the destination either keeps its old
/// content or holds the complete new one, never a partial copy, and a
/// running copy of the old binary is not modified in place.
#[cfg(feature = "setup")]
fn install_file_atomically(source: &Path, destination: &Path, mode: u32) -> std::io::Result<()> {
    use std::io;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "destination has no parent"))?;
    let name = destination
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "destination has no name"))?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id()
    ));

    let result = (|| {
        let mut input = fs::File::open(source)?;
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)?;
        io::copy(&mut input, &mut output)?;
        // The umask may have masked the mode at creation.
        output.set_permissions(fs::Permissions::from_mode(mode))?;
        output.sync_all()?;
        drop(output);
        fs::rename(&temporary, destination)?;
        // Make the rename durable as well.
        fs::File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(feature = "setup")]
fn run_command_checked(cmd: &mut Command, description: &str) -> Result<()> {
    let status = cmd
        .status()
        .map_err(|e| Error::Other(format!("failed to execute {description}: {e}")))?;
    if !status.success() {
        return Err(Error::Other(format!(
            "{description} failed with exit status {status}"
        )));
    }
    Ok(())
}

/// The unit confines the daemon to what it needs: netlink and IP sockets,
/// a read-only system with the PID file as the only write, no new
/// privileges and no access to home directories, kernel tunables or logs.
/// Capabilities are not restricted: the kernel autoloads the L2TP modules
/// and resolves names on the daemon's behalf, and the exact set differs
/// between kernels.
#[cfg(feature = "setup")]
fn systemd_unit_text() -> String {
    format!(
        "[Unit]\n\
         Description=rs-l2tpd daemon\n\
         Before=network-online.target\n\
         \n\
         [Service]\n\
         Type=forking\n\
         PIDFile={DEFAULT_PIDFILE_PATH}\n\
         ExecStart={INSTALL_BINARY_PATH}\n\
         ExecReload=/bin/kill -HUP $MAINPID\n\
         TimeoutStartSec=infinity\n\
         Restart=on-failure\n\
         RestartSec=3\n\
         \n\
         # Hardening: the daemon only needs netlink and IP sockets, and only\n\
         # writes its PID file.\n\
         NoNewPrivileges=yes\n\
         ProtectSystem=full\n\
         ProtectHome=yes\n\
         PrivateTmp=yes\n\
         ProtectKernelTunables=yes\n\
         ProtectKernelLogs=yes\n\
         ProtectControlGroups=yes\n\
         ProtectClock=yes\n\
         ProtectHostname=yes\n\
         RestrictRealtime=yes\n\
         RestrictSUIDSGID=yes\n\
         LockPersonality=yes\n\
         MemoryDenyWriteExecute=yes\n\
         SystemCallArchitectures=native\n\
         RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n\
         \n\
         [Install]\n\
         RequiredBy=network-online.target\n"
    )
}

#[cfg(feature = "setup")]
fn run_setup() -> Result<()> {
    ensure_root_uid()?;

    let current_exe = std::fs::read_link("/proc/self/exe")
        .or_else(|_| std::env::current_exe())
        .map_err(|e| Error::Other(format!("failed to resolve current executable path: {e}")))?;

    let install_binary = Path::new(INSTALL_BINARY_PATH);
    if let Some(parent) = install_binary.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::Other(format!(
                "failed to create install directory {}: {e}",
                parent.display()
            ))
        })?;
    }
    install_file_atomically(&current_exe, install_binary, 0o755).map_err(|e| {
        Error::Other(format!(
            "failed to install {} as {}: {e}",
            current_exe.display(),
            install_binary.display()
        ))
    })?;
    info!("installed binary at {}", install_binary.display());

    let service_file = Path::new(INSTALL_SYSTEMD_UNIT_PATH);
    if let Some(parent) = service_file.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::Other(format!(
                "failed to create systemd directory {}: {e}",
                parent.display()
            ))
        })?;
    }
    std::fs::write(service_file, systemd_unit_text()).map_err(|e| {
        Error::Other(format!(
            "failed to write systemd service unit {}: {e}",
            service_file.display()
        ))
    })?;
    info!("installed systemd unit at {}", service_file.display());

    let config_file = Path::new(CONFIG_FILE_PATH);
    if let Some(parent) = config_file.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::Other(format!(
                "failed to create config directory {}: {e}",
                parent.display()
            ))
        })?;
    }
    create_empty_file(config_file)?;
    std::fs::create_dir_all(CONFIG_DIR_PATH).map_err(|e| {
        Error::Other(format!(
            "failed to create config drop-in directory {}: {e}",
            CONFIG_DIR_PATH
        ))
    })?;
    info!(
        "ensured config file {} and drop-in directory {}",
        CONFIG_FILE_PATH, CONFIG_DIR_PATH
    );

    run_command_checked(
        Command::new("systemctl").arg("daemon-reload"),
        "systemctl daemon-reload",
    )?;
    run_command_checked(
        Command::new("systemctl")
            .arg("enable")
            .arg("--now")
            .arg("rs-l2tpd"),
        "systemctl enable --now rs-l2tpd",
    )?;
    info!("systemd service enabled and started");

    Ok(())
}

fn main() -> Result<()> {
    std::env::set_current_dir("/")
        .map_err(|e| Error::Other(format!("failed to change directory to /: {e}")))?;

    let args = Args::parse();

    let level = if args.verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    env_logger::Builder::new()
        .filter_level(level)
        .try_init()
        .map_err(|e| Error::Other(e.to_string()))?;

    #[cfg(feature = "setup")]
    if args.setup {
        run_setup()?;
        return Ok(());
    }

    // Start-up is lenient: whatever is usable is applied, even nothing, so
    // that one mistake does not keep every tunnel down. A reload (see
    // load_config_for_reload) also keeps the previous values of an entry it
    // cannot use, so that a mistake never takes a running tunnel down.
    let loaded = load_config_lenient();
    for problem in &loaded.errors {
        error!("configuration problem, left out: {problem}");
    }
    for problem in &loaded.warnings {
        warn!("configuration problem, {problem}");
    }
    if args.check {
        let rendered = toml::to_string_pretty(&loaded.config)
            .map_err(|e| Error::Other(format!("failed to render config as TOML: {e}")))?;
        println!("{rendered}");
        let count = loaded.errors.len() + loaded.warnings.len();
        if count > 0 {
            error!("{count} problem(s) found; the configuration above is what would be applied");
            std::process::exit(1);
        }
        return Ok(());
    }
    if !loaded.errors.is_empty() {
        warn!("starting with the usable part of the configuration only; fix the problems above and reload");
    }
    let initial_config = loaded.config;

    let readiness = unix_daemon::daemonize()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Other(format!("failed to create Tokio runtime: {e}")))?;

    runtime.block_on(run_daemon(initial_config, args.pidfile, readiness))
}

async fn run_daemon(
    initial_config: Config,
    pidfile: PathBuf,
    mut readiness: unix_daemon::ReadinessNotifier,
) -> Result<()> {
    let mut service = Service::new(initial_config).await?;
    install_signal_handlers(service.control())?;

    match service.converge().await {
        Ok(Startup::Converged) => {}
        Ok(Startup::ShutdownRequested) => {
            readiness.signal_failure();
            return Ok(());
        }
        Ok(_) => unreachable!("unknown startup outcome"),
        Err(e) => {
            readiness.signal_failure();
            return Err(e);
        }
    }

    if let Err(e) = unix_daemon::write_pid_file(&pidfile) {
        readiness.signal_failure();
        error!("{e}");
        // Dropping the service closes the tunnel sockets, which removes the
        // tunnels; shutdown does so in order and reports failures.
        if let Err(cleanup) = service.control().shutdown() {
            warn!("startup cleanup failed after pidfile error: {}", cleanup);
        }
        let control = service.control();
        if let Err(cleanup) = service.run(reload_with(control)).await {
            warn!("startup cleanup failed after pidfile error: {}", cleanup);
        }
        return Err(e);
    }
    if let Err(e) = readiness.signal_ready() {
        let control = service.control();
        let _ = control.shutdown();
        let _ = service.run(reload_with(control)).await;
        unix_daemon::remove_pid_file(pidfile);
        return Err(e);
    }

    info!("initial configuration applied");

    let control = service.control();
    let result = service.run(reload_with(control)).await;
    if let Err(e) = &result {
        error!("shutdown cleanup failed: {}", e);
    }

    unix_daemon::remove_pid_file(pidfile);

    result
}

#[cfg(test)]
mod tests {
    use super::{list_toml_files_at, load_config_for_reload_at, load_config_lenient_at, Config};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock monotonic")
            .as_nanos();
        path.push(format!(
            "rs-l2tpd-tests-{}-{}-{}",
            name,
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[test]
    fn list_toml_files_at_keeps_main_when_dropin_dir_missing() {
        let temp_dir = unique_temp_dir("config-main");
        let main_file = temp_dir.join("rs-l2tpd.toml");
        let dropin_dir = temp_dir.join("rs-l2tpd.toml.d");

        fs::write(&main_file, b"[tunnels]\n").expect("write main config");
        let files = list_toml_files_at(&main_file, &dropin_dir).expect("list files");

        assert_eq!(files, vec![main_file.clone()]);
        fs::remove_dir_all(temp_dir).expect("cleanup temp dir");
    }

    #[test]
    fn list_toml_files_at_sorts_and_filters() {
        let temp_dir = unique_temp_dir("config-sort");
        let main_file = temp_dir.join("rs-l2tpd.toml");
        let dropin_dir = temp_dir.join("rs-l2tpd.toml.d");

        fs::create_dir_all(&dropin_dir).expect("create dropin dir");
        fs::write(&main_file, b"[tunnels]\n").expect("write main config");
        fs::write(dropin_dir.join("20-extra.toml"), b"[tunnels]\n").expect("write dropin");
        fs::write(dropin_dir.join("10-base.toml"), b"[tunnels]\n").expect("write dropin");
        fs::write(dropin_dir.join("README.txt"), b"ignore\n").expect("write non toml");

        let files = list_toml_files_at(&main_file, &dropin_dir).expect("list files");

        let expected = vec![
            main_file.clone(),
            dropin_dir.join("10-base.toml"),
            dropin_dir.join("20-extra.toml"),
        ];
        assert_eq!(files, expected);

        fs::remove_dir_all(temp_dir).expect("cleanup temp dir");
    }

    #[test]
    fn list_toml_files_at_keeps_main_precedence_over_lexicographic_order() {
        let temp_dir = unique_temp_dir("config-precedence");
        let main_file = temp_dir.join("zz-main.toml");
        let dropin_dir = temp_dir.join("aa-dropins");

        fs::create_dir_all(&dropin_dir).expect("create dropin dir");
        fs::write(&main_file, b"[tunnels]\n").expect("write main config");
        fs::write(dropin_dir.join("00-first.toml"), b"[tunnels]\n").expect("write dropin");

        let files = list_toml_files_at(&main_file, &dropin_dir).expect("list files");
        let expected = vec![main_file.clone(), dropin_dir.join("00-first.toml")];
        assert_eq!(files, expected);

        fs::remove_dir_all(temp_dir).expect("cleanup temp dir");
    }

    #[test]
    fn load_config_at_merges_main_and_dropins() {
        let temp_dir = unique_temp_dir("config-load");
        let main_file = temp_dir.join("rs-l2tpd.toml");
        let dropin_dir = temp_dir.join("rs-l2tpd.toml.d");
        fs::create_dir_all(&dropin_dir).expect("create dropin dir");
        fs::write(
            &main_file,
            "[tunnels.tun0]\ntunnel_id = 10\nip_version = \"V6\"\nremote_addr = \"2001:db8::1\"\n\
             [sessions.sess0]\ntunnel_name = \"tun0\"\nsession_id = 100\ninterface_name = \"l2tp0\"\n",
        )
        .expect("write main config");
        fs::write(
            dropin_dir.join("10-rename.toml"),
            "[sessions.sess0]\ninterface_name = \"l2tp5\"\ninterface_hwaddr = \"02:00:5e:00:53:01\"\n",
        )
        .expect("write dropin");

        let config =
            load_config_for_reload_at(&main_file, &dropin_dir, &Config::new()).expect("load");
        let session = &config.sessions()["sess0"];
        assert_eq!(session.interface_name().to_str().unwrap(), "l2tp5");
        assert_eq!(
            session.interface_hwaddr().map(|a| a.to_string()).as_deref(),
            Some("02:00:5e:00:53:01")
        );
        assert_eq!(config.tunnels()["tun0"].tunnel_id(), 10);

        // A broken drop-in names its file and keeps the previous
        // configuration on a reload, since its entries cannot be told apart.
        fs::write(
            dropin_dir.join("20-bad.toml"),
            "[sessions.sess0]\ninterface_name = [\n",
        )
        .expect("write bad dropin");
        let err = load_config_for_reload_at(&main_file, &dropin_dir, &config).unwrap_err();
        assert!(err.to_string().contains("20-bad.toml"), "{err}");
        assert!(
            err.to_string()
                .contains("keeping the previous configuration"),
            "{err}"
        );

        // Leniently, the broken file is left out and the rest is used.
        let loaded = load_config_lenient_at(&main_file, &dropin_dir);
        assert_eq!(loaded.errors.len(), 1, "{:?}", loaded.errors);
        assert!(loaded.errors[0].contains("20-bad.toml"));
        assert!(loaded.warnings.is_empty());
        assert_eq!(
            loaded.config.sessions()["sess0"]
                .interface_name()
                .to_str()
                .unwrap(),
            "l2tp5"
        );

        let empty = load_config_for_reload_at(
            &temp_dir.join("absent.toml"),
            &temp_dir.join("absent.d"),
            &Config::new(),
        )
        .expect("load nothing");
        assert!(empty.tunnels().is_empty());
        fs::remove_dir_all(temp_dir).expect("cleanup temp dir");
    }

    #[test]
    fn lenient_loading_keeps_everything_usable_and_sorts_the_problems() {
        use rs_l2tpd::config::{IpHost, TunnelConfig};

        let temp_dir = unique_temp_dir("config-lenient");
        let main_file = temp_dir.join("rs-l2tpd.toml");
        let dropin_dir = temp_dir.join("rs-l2tpd.toml.d");
        fs::write(
            &main_file,
            "[tunnels.good]\ntunnel_id = 10\nremote_addr = \"2001:db8::1\"\n\
             [tunnels.soft]\ntunnel_id = 11\nip_version = \"V6\"\nremote_addr = \"192.0.2.1\"\n\
             [tunnels.hard]\ntunnel_id = 0\nremote_addr = \"2001:db8::3\"\n\
             [sessions.on-good]\ntunnel_name = \"good\"\nsession_id = 100\ninterface_name = \"l2tp0\"\n\
             [sessions.on-soft]\ntunnel_name = \"soft\"\nsession_id = 102\ninterface_name = \"l2tp1\"\n\
             [sessions.on-hard]\ntunnel_name = \"hard\"\nsession_id = 103\ninterface_name = \"l2tp3\"\n\
             [sessions.bad-mac]\ntunnel_name = \"good\"\nsession_id = 101\ninterface_name = \"l2tp2\"\n\
             interface_hwaddr = \"01:00:5e:00:53:01\"\n",
        )
        .expect("write main config");

        let loaded = load_config_lenient_at(&main_file, &dropin_dir);
        assert_eq!(
            loaded.config.tunnels().keys().collect::<Vec<_>>(),
            vec!["good", "soft"]
        );
        assert_eq!(
            loaded.config.sessions().keys().collect::<Vec<_>>(),
            vec!["bad-mac", "on-good", "on-soft"]
        );
        // An unusable endpoint keeps the tunnel, without a peer; an unusable
        // hardware address keeps the session, with the kernel's address.
        assert_eq!(
            loaded.config.tunnels()["soft"].remote_addr(),
            &IpHost::V6Addr(TunnelConfig::NO_PEER_ADDR)
        );
        assert_eq!(loaded.config.sessions()["bad-mac"].interface_hwaddr(), None);
        assert_eq!(
            loaded.errors,
            [
                "tunnel hard: tunnel_id is zero",
                "session on-hard: its tunnel hard was rejected",
            ]
        );
        assert_eq!(
            loaded.warnings,
            [
                "no peer until corrected: tunnel soft: remote_addr 192.0.2.1 is IPv4 but ip_version is IPv6",
                "kernel hardware address until corrected: session bad-mac: interface_hwaddr: hardware address 01:00:5e:00:53:01 is a multicast address",
            ]
        );

        // On a reload the new, broken entries are left out and the rest is
        // applied, with the same tolerance for the soft problems.
        let config = load_config_for_reload_at(&main_file, &dropin_dir, &Config::new())
            .expect("reload leaving the new broken entries out");
        assert_eq!(config, loaded.config);

        // An entry that was in force keeps its previous values instead.
        let mut previous = Config::new();
        previous
            .insert_tunnel(
                "hard",
                TunnelConfig::for_address(12, "2001:db8::3".parse().unwrap()),
            )
            .unwrap();
        previous
            .insert_session(
                "on-hard",
                rs_l2tpd::config::SessionConfig::new("hard", 103, "l2tp3".parse().unwrap()),
            )
            .unwrap();
        let config = load_config_for_reload_at(&main_file, &dropin_dir, &previous)
            .expect("reload keeping the previous values");
        assert_eq!(config.tunnels()["hard"], previous.tunnels()["hard"]);
        assert_eq!(config.sessions()["on-hard"], previous.sessions()["on-hard"]);
        assert_eq!(config.tunnels().len(), 3);
        assert_eq!(config.sessions().len(), 4);

        // Previous values that no longer fit keep the whole configuration.
        let mut previous = Config::new();
        previous
            .insert_tunnel(
                "hard",
                TunnelConfig::for_address(10, "2001:db8::3".parse().unwrap()),
            )
            .unwrap();
        let err = load_config_for_reload_at(&main_file, &dropin_dir, &previous).unwrap_err();
        assert!(err.to_string().contains("tunnel hard"), "{err}");
        assert!(
            err.to_string()
                .contains("keeping the previous configuration"),
            "{err}"
        );

        // With only the unusable endpoint left, a reload applies it.
        fs::write(
            &main_file,
            "[tunnels.good]\ntunnel_id = 10\nremote_addr = \"2001:db8::1\"\n\
             [tunnels.soft]\ntunnel_id = 11\nremote_addr = \"not a host!\"\n",
        )
        .expect("rewrite main config");
        let config = load_config_for_reload_at(&main_file, &dropin_dir, &Config::new())
            .expect("reload with a warning");
        assert_eq!(
            config.tunnels()["soft"].remote_addr(),
            &IpHost::V6Addr(TunnelConfig::NO_PEER_ADDR)
        );

        // Nothing usable at all is still a valid, empty configuration.
        fs::write(&main_file, "[tunnels.hard]\ntunnel_id = 0\n").expect("rewrite main config");
        let loaded = load_config_lenient_at(&main_file, &dropin_dir);
        assert!(loaded.config.tunnels().is_empty());
        assert_eq!(loaded.errors.len(), 1);
        fs::write(&main_file, "").expect("empty main config");
        let loaded = load_config_lenient_at(&main_file, &dropin_dir);
        assert!(loaded.config.tunnels().is_empty());
        assert!(loaded.errors.is_empty() && loaded.warnings.is_empty());
        fs::remove_dir_all(temp_dir).expect("cleanup temp dir");
    }

    #[test]
    fn a_bad_hardware_address_alone_does_not_refuse_a_reload() {
        let temp_dir = unique_temp_dir("config-bad-mac");
        let main_file = temp_dir.join("rs-l2tpd.toml");
        let dropin_dir = temp_dir.join("rs-l2tpd.toml.d");
        fs::write(
            &main_file,
            "[tunnels.good]\ntunnel_id = 10\nremote_addr = \"2001:db8::1\"\n\
             [sessions.bad-mac]\ntunnel_name = \"good\"\nsession_id = 101\ninterface_name = \"l2tp2\"\n\
             interface_hwaddr = \"02:00:5e:00:53\"\n",
        )
        .expect("write main config");
        let config = load_config_for_reload_at(&main_file, &dropin_dir, &Config::new())
            .expect("reload with a warning");
        assert_eq!(config.sessions()["bad-mac"].interface_hwaddr(), None);
        let loaded = load_config_lenient_at(&main_file, &dropin_dir);
        assert!(loaded.errors.is_empty());
        assert_eq!(loaded.warnings.len(), 1);
        assert!(
            loaded.warnings[0].starts_with(
                "kernel hardware address until corrected: session bad-mac: interface_hwaddr: invalid hardware address"
            ),
            "{:?}",
            loaded.warnings
        );
        fs::remove_dir_all(temp_dir).expect("cleanup temp dir");
    }

    #[test]
    fn write_pid_file_refuses_symlinks_and_sets_modes() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = unique_temp_dir("pidfile");
        let dir = temp_dir.join("run").join("nested");
        let pidfile = dir.join("rs-l2tpd.pid");
        super::unix_daemon::write_pid_file(&pidfile).expect("write pidfile");
        let contents = fs::read_to_string(&pidfile).expect("read pidfile");
        assert_eq!(contents.trim().parse::<u32>().unwrap(), std::process::id());
        assert_eq!(
            fs::metadata(&pidfile).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o755
        );

        let target = temp_dir.join("target");
        fs::write(&target, "1\n").unwrap();
        let link = temp_dir.join("link.pid");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(super::unix_daemon::write_pid_file(&link).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "1\n");

        fs::remove_dir_all(temp_dir).expect("cleanup temp dir");
    }

    #[test]
    fn write_pid_file_accepts_search_only_ancestors() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = unique_temp_dir("pidfile-search-only");
        let ancestor = temp_dir.join("searchable");
        let parent = ancestor.join("writable");
        fs::create_dir_all(&parent).unwrap();
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o111)).unwrap();
        let pidfile = parent.join("daemon.pid");
        let result = super::unix_daemon::write_pid_file(&pidfile);
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o755)).unwrap();
        result.expect("directory traversal needs search permission, not read permission");
        assert_eq!(
            fs::read_to_string(&pidfile).unwrap(),
            format!("{}\n", std::process::id())
        );
        fs::remove_dir_all(temp_dir).unwrap();
    }

    #[test]
    fn write_pid_file_updates_safe_precreated_file_in_nonwritable_directory() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        // Root can create the temporary file despite these mode bits;
        // this compatibility case concerns a daemon using network capabilities.
        // SAFETY: geteuid has no safety preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let temp_dir = unique_temp_dir("pidfile-precreated");
        let pidfile = temp_dir.join("daemon.pid");
        fs::write(&pidfile, "1234567890\n").unwrap();
        fs::set_permissions(&pidfile, fs::Permissions::from_mode(0o600)).unwrap();
        let inode = fs::metadata(&pidfile).unwrap().ino();
        fs::set_permissions(&temp_dir, fs::Permissions::from_mode(0o555)).unwrap();
        let result = super::unix_daemon::write_pid_file(&pidfile);
        fs::set_permissions(&temp_dir, fs::Permissions::from_mode(0o755)).unwrap();
        result.expect("safe precreated PID file remains usable without directory write permission");
        assert_eq!(
            fs::read_to_string(&pidfile).unwrap(),
            format!("{}\n", std::process::id())
        );
        assert_eq!(fs::metadata(&pidfile).unwrap().ino(), inode);
        assert_eq!(fs::metadata(&pidfile).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::read_dir(&temp_dir).unwrap().count(), 1);
        fs::remove_dir_all(temp_dir).unwrap();
    }

    #[test]
    fn write_pid_file_never_reuses_writable_or_hardlinked_inodes() {
        use std::os::unix::fs::PermissionsExt;

        // SAFETY: geteuid has no safety preconditions. Root bypasses the
        // permissions that cause the guarded fallback to run.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let temp_dir = unique_temp_dir("pidfile-unsafe-precreated");
        let pidfile = temp_dir.join("daemon.pid");
        for mode in [0o666, 0o660] {
            fs::write(&pidfile, "unchanged\n").unwrap();
            fs::set_permissions(&pidfile, fs::Permissions::from_mode(mode)).unwrap();
            fs::set_permissions(&temp_dir, fs::Permissions::from_mode(0o555)).unwrap();
            let result = super::unix_daemon::write_pid_file(&pidfile);
            fs::set_permissions(&temp_dir, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(
                result.is_err(),
                "mode {mode:o} must require fresh-inode publication"
            );
            assert_eq!(fs::read_to_string(&pidfile).unwrap(), "unchanged\n");
        }

        fs::set_permissions(&pidfile, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = temp_dir.join("alias");
        fs::hard_link(&pidfile, &alias).unwrap();
        fs::set_permissions(&temp_dir, fs::Permissions::from_mode(0o555)).unwrap();
        let result = super::unix_daemon::write_pid_file(&pidfile);
        fs::set_permissions(&temp_dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            result.is_err(),
            "an in-place update must not alter a hardlink target"
        );
        assert_eq!(fs::read_to_string(&alias).unwrap(), "unchanged\n");
        assert_eq!(fs::read_dir(&temp_dir).unwrap().count(), 2);
        fs::remove_dir_all(temp_dir).unwrap();
    }

    #[test]
    fn write_pid_file_replaces_legacy_inode_and_leaves_directory_permissions() {
        use std::io::{Seek, SeekFrom, Write};
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp_dir = unique_temp_dir("pidfile-legacy");
        let parent = temp_dir.join("run");
        let dir = parent.join("nested");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o775)).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        let pidfile = dir.join("daemon.pid");
        fs::write(&pidfile, "123\n").unwrap();
        fs::set_permissions(&pidfile, fs::Permissions::from_mode(0o666)).unwrap();
        let mut old_descriptor = fs::OpenOptions::new().write(true).open(&pidfile).unwrap();
        let old_inode = old_descriptor.metadata().unwrap().ino();

        super::unix_daemon::write_pid_file(&pidfile).unwrap();
        let expected = format!("{}\n", std::process::id());
        assert_eq!(fs::read_to_string(&pidfile).unwrap(), expected);
        assert_ne!(fs::metadata(&pidfile).unwrap().ino(), old_inode);
        assert_eq!(fs::metadata(&pidfile).unwrap().mode() & 0o777, 0o644);
        // Directories the daemon did not create keep their permissions.
        assert_eq!(fs::metadata(&parent).unwrap().mode() & 0o777, 0o775);
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o777);

        // A writer who opened the old world-writable file can still write
        // that inode, but can no longer alter the published PID.
        old_descriptor.seek(SeekFrom::Start(0)).unwrap();
        old_descriptor.write_all(b"999999\n").unwrap();
        old_descriptor.sync_all().unwrap();
        assert_eq!(fs::read_to_string(&pidfile).unwrap(), expected);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(temp_dir).unwrap();
    }

    #[test]
    fn write_pid_file_preserves_sticky_directories_and_follows_trusted_directory_symlinks() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp_dir = unique_temp_dir("pidfile-sticky");
        let shared = temp_dir.join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
        // Like /var/run -> /run, this is a trusted directory alias.
        let alias = temp_dir.join("alias");
        std::os::unix::fs::symlink("shared", &alias).unwrap();
        let pidfile = alias.join("daemon.pid");
        super::unix_daemon::write_pid_file(&pidfile).unwrap();
        super::unix_daemon::write_pid_file(&pidfile).unwrap();
        assert_eq!(fs::metadata(&shared).unwrap().mode() & 0o7777, 0o1777);
        assert_eq!(fs::metadata(&pidfile).unwrap().mode() & 0o777, 0o644);
        assert_eq!(fs::read_dir(&shared).unwrap().count(), 1);
        fs::remove_dir_all(temp_dir).unwrap();
    }

    #[test]
    fn write_pid_file_rejects_nonregular_entries_and_directory_symlink_loops() {
        use std::os::unix::ffi::OsStrExt;

        let temp_dir = unique_temp_dir("pidfile-types");
        let directory = temp_dir.join("directory.pid");
        fs::create_dir(&directory).unwrap();
        assert!(super::unix_daemon::write_pid_file(&directory).is_err());

        let fifo = temp_dir.join("fifo.pid");
        let fifo_name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: fifo_name is a valid NUL-terminated pathname.
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        assert!(super::unix_daemon::write_pid_file(&fifo).is_err());

        let loop_link = temp_dir.join("loop");
        std::os::unix::fs::symlink("loop", &loop_link).unwrap();
        assert!(super::unix_daemon::write_pid_file(&loop_link.join("daemon.pid")).is_err());
        fs::remove_dir_all(temp_dir).unwrap();
    }

    #[cfg(feature = "setup")]
    #[test]
    fn install_file_atomically_replaces_and_sets_mode() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = unique_temp_dir("install");
        let source = temp_dir.join("source");
        let destination = temp_dir.join("bin").join("rs-l2tpd");
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(&source, b"new binary").unwrap();
        fs::write(&destination, b"old binary").unwrap();

        super::install_file_atomically(&source, &destination, 0o755).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"new binary");
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o755
        );
        // No temporary file is left behind, on success or on failure.
        assert_eq!(
            fs::read_dir(destination.parent().unwrap()).unwrap().count(),
            1
        );
        assert!(
            super::install_file_atomically(&temp_dir.join("absent"), &destination, 0o755).is_err()
        );
        assert_eq!(fs::read(&destination).unwrap(), b"new binary");
        assert_eq!(
            fs::read_dir(destination.parent().unwrap()).unwrap().count(),
            1
        );

        fs::remove_dir_all(temp_dir).unwrap();
    }

    #[cfg(feature = "setup")]
    #[test]
    fn systemd_unit_keeps_its_contract_and_is_hardened() {
        let unit = super::systemd_unit_text();
        for line in [
            "Type=forking",
            "PIDFile=/run/rs-l2tpd.pid",
            "ExecStart=/usr/local/bin/rs-l2tpd",
            "ExecReload=/bin/kill -HUP $MAINPID",
            "TimeoutStartSec=infinity",
            "Before=network-online.target",
            "RequiredBy=network-online.target",
            "NoNewPrivileges=yes",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
        ] {
            assert!(unit.lines().any(|l| l == line), "missing {line}");
        }
    }
}
