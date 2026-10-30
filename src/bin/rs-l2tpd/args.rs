//! Hand-written command line (P27).
use std::ffi::OsString;
use std::path::PathBuf;

#[cfg(feature = "setup-systemd")]
pub const USAGE: &str = "usage: rs-l2tpd [--config FILE] [--config-dir DIR] [--pid-file FILE] [--verbose]\n       [--check | --foreground | --restart | --adopt-version | --version | --setup-systemd [--prefix DIR]]";

#[cfg(not(feature = "setup-systemd"))]
pub const USAGE: &str = "usage: rs-l2tpd [--config FILE] [--config-dir DIR] [--pid-file FILE] [--verbose]\n       [--check | --foreground | --restart | --adopt-version | --version]";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Daemon,
    Foreground,
    Check,
    Restart,
    AdoptVersion,
    Version,
    Setup,
}

#[derive(Clone)]
pub struct Args {
    pub mode: Mode,
    pub config: PathBuf,
    pub config_dir: PathBuf,
    pub pid_file: PathBuf,
    pub verbose: bool,
    pub prefix: Option<PathBuf>,
}
impl Args {
    pub fn parse(input: impl IntoIterator<Item = OsString>) -> Result<Self, String> {
        let mut args = Self {
            mode: Mode::Daemon,
            config: env!("CONFIG_FILE_PATH").into(),
            config_dir: env!("CONFIG_DIR_PATH").into(),
            pid_file: env!("PID_FILE_PATH").into(),
            verbose: false,
            prefix: None,
        };
        let mut input = input.into_iter();
        while let Some(option) = input.next() {
            let mode = match option.to_str() {
                Some("--config" | "--config-dir" | "--pid-file" | "--prefix") => {
                    let value = input
                        .next()
                        .filter(|v| !v.is_empty())
                        .ok_or_else(|| format!("missing argument for {}", option.display()))?;
                    match option.to_str().unwrap() {
                        "--config" => args.config = value.into(),
                        "--config-dir" => args.config_dir = value.into(),
                        "--pid-file" => args.pid_file = value.into(),
                        _ => args.prefix = Some(value.into()),
                    }
                    continue;
                }
                Some("--verbose") => {
                    args.verbose = true;
                    continue;
                }
                Some("--check") => Mode::Check,
                Some("--foreground") => Mode::Foreground,
                Some("--restart") => Mode::Restart,
                Some("--adopt-version") => Mode::AdoptVersion,
                Some("--version") => Mode::Version,
                Some("--setup-systemd") if cfg!(feature = "setup-systemd") => Mode::Setup,
                _ => return Err(format!("unknown option: {}", option.display())),
            };
            if args.mode != Mode::Daemon {
                return Err("modes are exclusive".into());
            }
            args.mode = mode;
        }
        if args.prefix.is_some() && args.mode != Mode::Setup {
            return Err("--prefix requires --setup-systemd".into());
        }
        Ok(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(s: &str) -> Result<Args, String> {
        Args::parse(s.split_whitespace().map(Into::into))
    }
    /// spec: P27 C1
    #[test]
    fn byte_paths_and_option_like_values() {
        use std::os::unix::ffi::OsStringExt;
        for option in ["--config", "--config-dir", "--pid-file"] {
            for value in [
                OsString::from("--x"),
                OsString::from_vec(vec![b'-', b'-', 255]),
            ] {
                let args = Args::parse([option.into(), value.clone()]).unwrap();
                let path = match option {
                    "--config" => args.config,
                    "--config-dir" => args.config_dir,
                    _ => args.pid_file,
                };
                assert_eq!(path.into_os_string(), value);
            }
            assert!(Args::parse([option.into(), OsString::new()]).is_err());
        }
        assert_eq!(
            USAGE.contains("--setup-systemd"),
            cfg!(feature = "setup-systemd")
        );
        assert_eq!(USAGE.contains("--prefix"), cfg!(feature = "setup-systemd"));
    }
    /// spec: P27
    #[test]
    fn modes_and_errors() {
        for mode in [
            "--check",
            "--foreground",
            "--restart",
            "--adopt-version",
            "--version",
        ] {
            assert!(parse(mode).is_ok());
            assert!(parse(&format!("{mode} --check")).is_err());
        }
        for bad in [
            "--config",
            "--config-dir",
            "--pid-file",
            "--unknown",
            "--prefix /tmp",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        let a = parse("--config /a --config-dir /b --pid-file /c --verbose").unwrap();
        assert_eq!(a.config, PathBuf::from("/a"));
        assert_eq!(a.config_dir, PathBuf::from("/b"));
        assert_eq!(a.pid_file, PathBuf::from("/c"));
        assert!(a.verbose);
        assert_eq!(
            parse("--setup-systemd --prefix /tmp").is_ok(),
            cfg!(feature = "setup-systemd")
        );
    }
}
