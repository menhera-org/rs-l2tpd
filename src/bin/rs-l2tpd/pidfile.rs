//! Inode-based PID-file publication/removal (P10–P11).
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

#[derive(Clone)]
pub struct PidFile {
    pub path: PathBuf,
    pub dev: u64,
    pub ino: u64,
}
fn cstr(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in PID path"))
}
fn cvt(fd: i32) -> io::Result<OwnedFd> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}
fn directory(path: &Path, create: bool) -> io::Result<(OwnedFd, CString)> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let name = cstr(
        path.file_name()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "PID path needs a file name")
            })?
            .as_bytes(),
    )?;
    let mut dir = cvt(unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    })?;
    for component in path.parent().unwrap().components() {
        let value = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(value) => value,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "PID path contains ..",
                ));
            }
        };
        let value = cstr(value.as_bytes())?;
        let mut fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                value.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if create && fd < 0 && io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
            if unsafe { libc::mkdirat(dir.as_raw_fd(), value.as_ptr(), 0o755) } < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(error);
                }
            } else {
                let created = cvt(unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        value.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                })?;
                if unsafe { libc::fchmod(created.as_raw_fd(), 0o755) } < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    value.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
        }
        dir = cvt(fd)?;
        if !create {
            continue;
        }
        let metadata = File::from(dir.try_clone()?).metadata()?;
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != 0 && metadata.uid() != uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "PID directory is not owned by root or daemon user",
            ));
        }
        // kernel: fs/namei.c __check_sticky/may_delete (v6.8, v7.3); P10.
        if metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0 {
            log::warn!(
                "PID directory permits replacement by other users: {}",
                path.display()
            );
        }
    }
    Ok((dir, name))
}
fn inspect(dir: &OwnedFd, name: &CString) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::uninit();
    if unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } < 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { stat.assume_init() })
    }
}
impl PidFile {
    pub fn publish(path: &Path) -> io::Result<Self> {
        let (dir, name) = directory(path, true)?;
        let before = match inspect(&dir, &name) {
            Ok(stat) if stat.st_mode & libc::S_IFMT == libc::S_IFLNK => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "PID file is a symbolic link",
                ));
            }
            Ok(stat) => Some(stat),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        let mut random = [0; 8];
        getrandom::fill(&mut random).map_err(|e| io::Error::other(e.to_string()))?;
        let temporary =
            cstr(format!(".rs-l2tpd-{:016x}.pid", u64::from_ne_bytes(random)).as_bytes())?;
        let new = cvt(unsafe {
            libc::openat(
                dir.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        });
        let (mut file, fresh) = match new {
            Ok(fd) => (File::from(fd), true),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EACCES | libc::EROFS | libc::EPERM)
                ) =>
            {
                let before = before.ok_or(error)?;
                let fd = cvt(unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                    )
                })?;
                let file = File::from(fd);
                let m = file.metadata()?;
                if m.dev() != before.st_dev
                    || m.ino() != before.st_ino
                    || !m.is_file()
                    || m.uid() != unsafe { libc::geteuid() }
                    || m.nlink() != 1
                    || m.mode() & 0o022 != 0
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "unsafe pre-created PID file",
                    ));
                }
                (file, false)
            }
            Err(error) => return Err(error),
        };
        let result = (|| {
            if fresh {
                file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o644))?;
            }
            file.set_len(0)?;
            writeln!(file, "{}", std::process::id())?;
            file.sync_all()?;
            let metadata = file.metadata()?;
            if fresh {
                if let Ok(stat) = inspect(&dir, &name)
                    && stat.st_mode & libc::S_IFMT == libc::S_IFLNK
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "PID file became a symbolic link",
                    ));
                }
                if unsafe {
                    libc::renameat(
                        dir.as_raw_fd(),
                        temporary.as_ptr(),
                        dir.as_raw_fd(),
                        name.as_ptr(),
                    )
                } < 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(Self {
                path: path.to_owned(),
                dev: metadata.dev(),
                ino: metadata.ino(),
            })
        })();
        if fresh {
            unsafe {
                libc::unlinkat(dir.as_raw_fd(), temporary.as_ptr(), 0);
            }
        }
        result
    }
    pub fn matches(&self) -> io::Result<bool> {
        match std::fs::symlink_metadata(&self.path) {
            Ok(m) => Ok(m.is_file() && m.dev() == self.dev && m.ino() == self.ino),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
    pub fn remove(&self) -> io::Result<()> {
        let (dir, name) = match directory(&self.path, false) {
            Ok(result) => result,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                log::warn!(
                    "PID file cleanup could not inspect {}: {e}; leaving it alone",
                    self.path.display()
                );
                return Ok(());
            }
        };
        let stat = match inspect(&dir, &name) {
            Ok(stat) => stat,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                log::warn!(
                    "PID file cleanup could not inspect {}: {e}; leaving it alone",
                    self.path.display()
                );
                return Ok(());
            }
        };
        if stat.st_dev != self.dev
            || stat.st_ino != self.ino
            || stat.st_mode & libc::S_IFMT != libc::S_IFREG
        {
            log::warn!(
                "PID file was replaced; leaving {} alone",
                self.path.display()
            );
            return Ok(());
        }
        if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::testdir::Dir;
    use std::os::unix::fs::{PermissionsExt, symlink};
    /// spec: P10 P11
    #[test]
    fn fresh_inode_and_conditional_removal() {
        let dir = Dir::new();
        let path = dir.path().join("sub/daemon.pid");
        let first = PidFile::publish(&path).unwrap();
        let held = File::open(&path).unwrap();
        let second = PidFile::publish(&path).unwrap();
        assert_ne!(first.ino, second.ino);
        assert_eq!(held.metadata().unwrap().ino(), first.ino);
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o644);
        assert_eq!(
            std::fs::metadata(path.parent().unwrap()).unwrap().mode() & 0o777,
            0o755
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{}\n", std::process::id())
        );
        first.remove().unwrap();
        assert!(second.matches().unwrap());
        second.remove().unwrap();
        assert!(!path.exists());
    }
    /// spec: P11, P26, G2
    #[test]
    fn incorrect_inode_hints_and_nonregular_paths_never_authorize_removal() {
        crate::logger::init(true);
        let dir = Dir::new();
        let pid = PidFile::publish(&dir.path().join("daemon.pid")).unwrap();
        let contents = std::fs::read(&pid.path).unwrap();
        for (dev, ino) in [(pid.dev ^ 1, pid.ino), (pid.dev, pid.ino ^ 1)] {
            let hint = PidFile {
                path: pid.path.clone(),
                dev,
                ino,
            };
            assert!(!hint.matches().unwrap());
            hint.remove().unwrap();
            assert_eq!(std::fs::read(&pid.path).unwrap(), contents);
        }
        let link = dir.path().join("alias");
        symlink(&pid.path, &link).unwrap();
        for path in [dir.path(), link.as_path()] {
            let metadata = std::fs::symlink_metadata(path).unwrap();
            let hint = PidFile {
                path: path.to_owned(),
                dev: metadata.dev(),
                ino: metadata.ino(),
            };
            assert!(!hint.matches().unwrap());
            hint.remove().unwrap();
            assert_eq!(
                std::fs::symlink_metadata(path).unwrap().ino(),
                metadata.ino()
            );
            assert_eq!(std::fs::read(&pid.path).unwrap(), contents);
        }
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(pid.matches().unwrap());
        pid.remove().unwrap();
        assert!(!pid.path.exists());
        assert!(
            std::fs::symlink_metadata(link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    /// spec: P10 P11
    #[test]
    fn symlink_refusal_and_directory_permissions_preserved() {
        let dir = Dir::new();
        let parent = dir.path().join("trusted");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, PermissionsExt::from_mode(0o750)).unwrap();
        let link = dir.path().join("link");
        symlink(&parent, &link).unwrap();
        let path = link.join("daemon.pid");
        let pid = PidFile::publish(&path).unwrap();
        assert_eq!(std::fs::metadata(&parent).unwrap().mode() & 0o777, 0o750);
        std::fs::remove_file(&path).unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        symlink(&victim, &path).unwrap();
        assert!(PidFile::publish(&path).is_err());
        pid.remove().unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
    }
    /// spec: P10, P11
    #[test]
    fn invalid_paths_and_missing_files_leave_other_inodes_alone() {
        let dir = Dir::new();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        for path in [
            PathBuf::from("/"),
            PathBuf::from("nul\0pid"),
            dir.path().join("nul\0parent/pid"),
            dir.path().join("../victim"),
        ] {
            assert_eq!(
                PidFile::publish(&path).err().unwrap().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert_eq!(
            PidFile::publish(&victim.join("pid"))
                .err()
                .unwrap()
                .raw_os_error(),
            Some(libc::ENOTDIR)
        );
        let pid = PidFile::publish(&dir.path().join("sub/pid")).unwrap();
        std::fs::remove_file(&pid.path).unwrap();
        assert!(!pid.matches().unwrap());
        pid.remove().unwrap();
        std::fs::remove_dir(pid.path.parent().unwrap()).unwrap();
        pid.remove().unwrap();
        let invalid = PidFile {
            path: victim.join("pid"),
            ..pid
        };
        assert_eq!(
            invalid.matches().unwrap_err().raw_os_error(),
            Some(libc::ENOTDIR)
        );
        invalid.remove().unwrap();
        assert_eq!(std::fs::read_to_string(victim).unwrap(), "keep");
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod permission_tests {
    use super::*;
    use crate::testdir::Dir;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    /// spec: P10
    #[test]
    fn precreated_child() {
        let Some(path) = std::env::var_os("PID_PRECREATED_PATH") else {
            return;
        };
        let path = Path::new(&path);
        let before = std::fs::metadata(path).unwrap();
        let result = PidFile::publish(path);
        if std::env::var_os("PID_EXPECT_REFUSAL").is_some() {
            assert_eq!(
                result.err().unwrap().to_string(),
                "unsafe pre-created PID file"
            );
        } else {
            let published = result.unwrap();
            assert_eq!(published.ino, before.ino());
            assert_eq!(
                std::fs::read_to_string(path).unwrap(),
                format!("{}\n", std::process::id())
            );
        }
    }
    /// spec: P10
    #[test]
    #[ignore = "root in an isolated container, drops child uid"]
    fn precreated_permissions_links_and_owner() {
        let dir = Dir::new();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let path = dir.path().join("pid");
        for case in ["safe", "writable", "linked", "foreign"] {
            std::fs::write(&path, "old").unwrap();
            let name = cstr(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(
                unsafe {
                    libc::chown(
                        name.as_ptr(),
                        if case == "foreign" { 0 } else { 65534 },
                        65534,
                    )
                },
                0
            );
            std::fs::set_permissions(
                &path,
                std::fs::Permissions::from_mode(match case {
                    "writable" => 0o620,
                    "foreign" => 0o666,
                    _ => 0o600,
                }),
            )
            .unwrap();
            let link = dir.path().join("hardlink");
            if case == "linked" {
                std::fs::hard_link(&path, &link).unwrap();
            }
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .arg("--exact")
                .arg("pidfile::permission_tests::precreated_child")
                .arg("--nocapture")
                .env("PID_PRECREATED_PATH", &path)
                .uid(65534)
                .gid(65534);
            if case != "safe" {
                child.env("PID_EXPECT_REFUSAL", "1");
            }
            assert!(child.status().unwrap().success(), "{case}");
            std::fs::remove_file(&path).unwrap();
            if link.exists() {
                std::fs::remove_file(link).unwrap();
            }
        }
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let name = cstr(dir.path().as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(name.as_ptr(), 65534, 65534) }, 0);
        let error = PidFile::publish(&path).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            error.to_string(),
            "PID directory is not owned by root or daemon user"
        );
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
        assert_eq!(unsafe { libc::chown(name.as_ptr(), 0, 0) }, 0);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod removal_tests {
    use super::*;
    use crate::testdir::Dir;
    /// spec: P11
    #[test]
    fn uninspectable_removal_is_not_a_shutdown_failure() {
        let dir = Dir::new();
        let parent = dir.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        let path = parent.join("pid");
        let pid = PidFile::publish(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&parent).unwrap();
        std::fs::write(&parent, "replacement").unwrap();
        pid.remove().unwrap();
        assert_eq!(std::fs::read_to_string(parent).unwrap(), "replacement");
    }
    /// spec: P10 P11
    #[test]
    #[ignore = "root in an isolated container, changes directory owner"]
    fn removal_uses_inode_after_directory_owner_changes() {
        let dir = Dir::new();
        let parent = dir.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        let path = parent.join("pid");
        let pid = PidFile::publish(&path).unwrap();
        let name = cstr(parent.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(name.as_ptr(), 65534, 65534) }, 0);
        pid.remove().unwrap();
        assert!(!path.exists());
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod edge_tests {
    use super::*;
    use crate::testdir::Dir;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    /// spec: P10 P11
    #[test]
    fn pid_edge_child() {
        let Some(case) = std::env::var_os("PHASE5_PID_CASE") else {
            return;
        };
        crate::logger::init(false);
        let dir = Dir::new();
        let path = dir.path().join("pid");
        let reader = if case == "fifo" {
            let name = cstr(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            Some(
                cvt(unsafe {
                    libc::open(
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
                    )
                })
                .unwrap(),
            )
        } else {
            std::fs::write(&path, "old").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            None
        };
        let inode = std::fs::metadata(&path).unwrap().ino();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let errno = match case.to_str().unwrap() {
            "eperm" | "fifo" => Some(libc::EPERM),
            "erofs" => Some(libc::EROFS),
            "eacces" => Some(libc::EACCES),
            "eio" => Some(libc::EIO),
            _ => None,
        };
        if let Some(errno) = errno {
            // Deny only O_CREAT openat; opening the pre-created inode still reaches the kernel.
            let stmt = |code: u32, k| libc::sock_filter {
                code: code as u16,
                jt: 0,
                jf: 0,
                k,
            };
            let mut filter = [
                stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0),
                libc::sock_filter {
                    code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 3,
                    k: libc::SYS_openat as u32,
                },
                stmt(
                    libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
                    32 + if cfg!(target_endian = "little") { 0 } else { 4 },
                ),
                libc::sock_filter {
                    code: (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 1,
                    k: libc::O_CREAT as u32,
                },
                stmt(
                    libc::BPF_RET | libc::BPF_K,
                    libc::SECCOMP_RET_ERRNO | errno as u32,
                ),
                stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW),
            ];
            let program = libc::sock_fprog {
                len: filter.len() as u16,
                filter: filter.as_mut_ptr(),
            };
            assert_eq!(
                unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                0
            );
            assert_eq!(
                unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) },
                0
            );
        } else {
            let mode = if case == "sticky" { 0o1777 } else { 0o777 };
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let result = PidFile::publish(&path);
        if case == "eio" {
            assert_eq!(result.err().unwrap().raw_os_error(), Some(libc::EIO));
            assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "old");
            return;
        }
        if case == "fifo" {
            assert_eq!(
                result.err().unwrap().to_string(),
                "unsafe pre-created PID file"
            );
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            assert!(metadata.file_type().is_fifo());
            assert_eq!(metadata.ino(), inode);
            drop(reader);
            return;
        }
        let pid = result.unwrap();
        assert_eq!(pid.ino == inode, errno.is_some());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{}\n", std::process::id())
        );
        pid.remove().unwrap();
        assert!(!path.exists());
    }
    /// spec: P10 P11
    #[test]
    fn sticky_warning_and_unwritable_directory_fallbacks() {
        let mut ancestor_warnings = None;
        for case in [
            "sticky", "writable", "eperm", "erofs", "eacces", "eio", "fifo",
        ] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "pidfile::edge_tests::pid_edge_child",
                    "--nocapture",
                ])
                .env("PHASE5_PID_CASE", case)
                .output()
                .unwrap();
            assert!(output.status.success(), "{case}: {output:?}");
            let logs = String::from_utf8(output.stderr).unwrap();
            assert!(!logs.contains("LLVM Profile"), "{case}: {logs}");
            let warnings = logs.matches("PID directory permits replacement").count();
            let baseline = *ancestor_warnings.get_or_insert(warnings);
            assert_eq!(
                warnings,
                baseline + usize::from(case == "writable"),
                "{case}: {logs}"
            );
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod fault_tests {
    use super::*;

    /// spec: P10, P11, G2
    #[test]
    fn a_symlink_inserted_during_publication_never_receives_pid_contents() {
        const CHILD: &str = "RS_L2TPD_PID_SYMLINK_RACE";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = std::path::PathBuf::from(root);
            crate::syscall_barrier::stop().unwrap();
            let error = PidFile::publish(&root.join("daemon.pid")).err().unwrap();
            assert!(error.to_string().contains("became a symbolic link"));
            assert_eq!(
                std::fs::read(root.join("target")).unwrap(),
                b"operator data"
            );
            assert_eq!(
                std::fs::read_link(root.join("daemon.pid")).unwrap(),
                root.join("target")
            );
            assert!(std::fs::read_dir(&root).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .as_bytes()
                    .starts_with(b".rs-l2tpd-")
            }));
            println!("PID_SYMLINK_RACE_CHECKED=1");
            return;
        }
        let dir = crate::testdir::Dir::new();
        let target = dir.path().join("target");
        std::fs::write(&target, b"operator data").unwrap();
        let mut changed = false;
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "pidfile::fault_tests::a_symlink_inserted_during_publication_never_receives_pid_contents", "--nocapture"])
            .env(CHILD, dir.path());
        let output =
            crate::syscall_barrier::run(&mut command, dir.path(), |tid, number, arguments| {
                if !changed && number == libc::SYS_fsync as u64 {
                    let path = std::fs::read_link(format!("/proc/{tid}/fd/{}", arguments[0]))?;
                    if path.parent() == Some(dir.path())
                        && path
                            .file_name()
                            .unwrap()
                            .as_bytes()
                            .starts_with(b".rs-l2tpd-")
                    {
                        std::os::unix::fs::symlink(&target, dir.path().join("daemon.pid"))?;
                        changed = true;
                    }
                }
                Ok(())
            })
            .unwrap();
        assert!(changed, "the PID temporary file must reach fsync");
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("PID_SYMLINK_RACE_CHECKED=1"));
    }
    use crate::testdir::Dir;

    /// spec: P10, P11, P17
    #[test]
    fn pid_syscall_fault_child() {
        let Some(case) = std::env::var_os("PHASE6_PID_SYSCALL") else {
            return;
        };
        let case = case.to_str().unwrap();
        crate::logger::init(false);
        let root = PathBuf::from(std::env::var_os("PHASE6_PID_ROOT").unwrap());
        let path = root.join(if case.starts_with("mkdir") {
            "new/pid"
        } else {
            "pid"
        });
        let syscalls: &[libc::c_long] = match case {
            "mkdir" | "mkdir-race" => &[libc::SYS_mkdirat],
            "mkdir-mode" => &[libc::SYS_fchmod],
            "truncate" => &[
                libc::SYS_ftruncate,
                #[cfg(target_pointer_width = "32")]
                libc::SYS_ftruncate64,
            ],
            "sync" => &[libc::SYS_fsync],
            "rename" => &[
                #[cfg(not(any(
                    target_arch = "riscv32",
                    target_arch = "riscv64",
                    target_arch = "loongarch64"
                )))]
                libc::SYS_renameat,
                libc::SYS_renameat2,
            ],
            "unlink" => &[libc::SYS_unlinkat],
            "random" => &[libc::SYS_getrandom],
            "remove-open" => &[],
            #[cfg(target_pointer_width = "64")]
            "publish-inspect" => &[],
            #[cfg(target_pointer_width = "64")]
            "remove-inspect" | "matches" => &[
                libc::SYS_newfstatat,
                libc::SYS_statx,
                #[cfg(any(
                    target_arch = "x86_64",
                    target_arch = "powerpc64",
                    target_arch = "s390x",
                    target_arch = "sparc64",
                    target_arch = "mips64",
                    target_arch = "mips64r6"
                ))]
                libc::SYS_lstat,
            ],
            _ => panic!("unknown PID fault fixture"),
        };
        let errno = match case {
            "mkdir-race" => libc::EEXIST,
            _ => libc::EIO,
        };
        let prepared = matches!(
            case,
            "unlink" | "remove-open" | "remove-inspect" | "matches"
        )
        .then(|| {
            let metadata = std::fs::metadata(&path).unwrap();
            PidFile {
                path: path.clone(),
                dev: metadata.dev(),
                ino: metadata.ino(),
            }
        });
        if case == "publish-inspect" {
            #[cfg(coverage_nightly)]
            crate::syscall_fault::keep_profile_output();
            #[cfg(target_pointer_width = "64")]
            for flags in [
                libc::AT_SYMLINK_NOFOLLOW,
                libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT,
            ] {
                crate::syscall_fault::on_exec_argument(
                    libc::SYS_newfstatat,
                    3,
                    flags as u32,
                    errno,
                )()
                .unwrap();
                crate::syscall_fault::on_exec_argument(libc::SYS_statx, 2, flags as u32, errno)()
                    .unwrap();
            }
            #[cfg(any(
                target_arch = "x86_64",
                target_arch = "powerpc64",
                target_arch = "s390x",
                target_arch = "sparc64",
                target_arch = "mips64",
                target_arch = "mips64r6"
            ))]
            crate::syscall_fault::on_exec(&[libc::SYS_lstat], errno)().unwrap();
        } else if case == "remove-open" {
            crate::syscall_fault::refuse_open(errno);
        } else {
            crate::syscall_fault::refuse(syscalls, errno);
        }
        if case.starts_with("remove-") {
            prepared.as_ref().unwrap().remove().unwrap();
            return;
        }
        let entropy_error = (case == "random").then(|| {
            let error = getrandom::fill(&mut [0; 8]).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(errno));
            error.to_string()
        });
        let result = if case == "unlink" {
            prepared.as_ref().unwrap().remove()
        } else if case == "matches" {
            prepared.as_ref().unwrap().matches().map(|_| ())
        } else {
            PidFile::publish(&path).map(|_| ())
        };
        let error = result.unwrap_err();
        if let Some(expected) = entropy_error {
            assert_eq!(error.kind(), io::ErrorKind::Other);
            assert_eq!(error.to_string(), expected);
        } else {
            assert_eq!(
                error.raw_os_error(),
                Some(if case == "mkdir-race" {
                    libc::ENOENT
                } else {
                    errno
                })
            );
        }
    }

    /// spec: P10, P11, P17
    #[test]
    fn publication_and_removal_faults_preserve_existing_files_and_clear_temporary_names() {
        for case in [
            "mkdir",
            "mkdir-race",
            "mkdir-mode",
            "truncate",
            "sync",
            "rename",
            "unlink",
            "random",
            "remove-open",
            #[cfg(target_pointer_width = "64")]
            "publish-inspect",
            #[cfg(target_pointer_width = "64")]
            "remove-inspect",
            #[cfg(target_pointer_width = "64")]
            "matches",
        ] {
            let dir = Dir::new();
            let existing = dir.path().join("pid");
            std::fs::write(&existing, "keep").unwrap();
            let inode = std::fs::metadata(&existing).unwrap().ino();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "pidfile::fault_tests::pid_syscall_fault_child",
                    "--nocapture",
                ])
                .env("PHASE6_PID_SYSCALL", case)
                .env("PHASE6_PID_ROOT", dir.path())
                .output()
                .unwrap();
            assert!(output.status.success(), "{case}: {output:?}");
            let logs = String::from_utf8(output.stderr).unwrap();
            assert!(!logs.contains("LLVM Profile"), "{case}: {logs}");
            assert_eq!(
                logs.matches("PID file cleanup could not inspect").count(),
                usize::from(case.starts_with("remove-")),
                "{case}: {logs}"
            );
            assert_eq!(std::fs::metadata(&existing).unwrap().ino(), inode, "{case}");
            assert_eq!(std::fs::read_to_string(existing).unwrap(), "keep", "{case}");
            assert!(!dir.path().join("new/pid").exists(), "{case}");
            for entry in std::fs::read_dir(dir.path()).unwrap() {
                assert!(
                    !entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".rs-l2tpd-"),
                    "{case}: temporary PID file remains"
                );
            }
        }
    }
}
