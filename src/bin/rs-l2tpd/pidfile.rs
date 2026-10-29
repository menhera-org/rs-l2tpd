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
        let metadata = File::from(dir.try_clone()?).metadata()?;
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != 0 && metadata.uid() != uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "PID directory is not owned by root or daemon user",
            ));
        }
        if metadata.mode() & 0o022 != 0 {
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
            Err(error) if matches!(error.raw_os_error(), Some(libc::EACCES | libc::EROFS)) => {
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
            Err(e) => return Err(e),
        };
        let stat = match inspect(&dir, &name) {
            Ok(stat) => stat,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
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
}

#[cfg(test)]
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
            assert!(result.is_err());
        } else {
            let published = result.unwrap();
            assert_eq!(published.ino, before.ino());
            assert_eq!(
                std::fs::read_to_string(path).unwrap(),
                format!("{}\n", std::process::id())
            );
        }
    }
    /// spec: P10 C3
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
                std::fs::Permissions::from_mode(if case == "writable" { 0o620 } else { 0o600 }),
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
    }
}
