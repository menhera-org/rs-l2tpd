//! Build static daemon packages without Debian build tools or Rust dependencies.
mod archive;
mod elf;

use archive::Entry;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

const TARGETS: [(&str, &str, u16); 2] = [
    ("x86_64-unknown-linux-musl", "amd64", 62),
    ("aarch64-unknown-linux-musl", "arm64", 183),
];

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn version(manifest: &str) -> io::Result<&str> {
    let package = manifest
        .split("[package]")
        .nth(1)
        .ok_or_else(|| invalid("missing [package]"))?;
    for line in package
        .lines()
        .take_while(|line| !line.trim_start().starts_with('['))
    {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() == "version" {
            let value = value
                .trim()
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .ok_or_else(|| invalid("package version must be a quoted string"))?;
            if value.is_empty()
                || !value.starts_with(|c: char| c.is_ascii_digit())
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
            {
                return Err(invalid("unsupported package version"));
            }
            return Ok(value);
        }
    }
    Err(invalid("missing package version"))
}

fn checked(command: &mut Command) -> io::Result<()> {
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("build command failed: {status}")))
    }
}

fn build(root: &Path, target: &str) -> io::Result<PathBuf> {
    let output = root.join("target/musl-deb-build");
    checked(
        Command::new(root.join("build-release.sh"))
            .current_dir(root)
            .env("FEATURES", "bin")
            .env("CONFIG_FILE_PATH", "/etc/rs-l2tpd.toml")
            .env("CONFIG_DIR_PATH", "/etc/rs-l2tpd.toml.d")
            .env("PID_FILE_PATH", "/run/rs-l2tpd.pid")
            .env("TARGETS", target)
            .env("CROSS_TARGET_DIR", &output)
            .arg("--no-default-features"),
    )?;
    Ok(output.join(target).join(target).join("release/rs-l2tpd"))
}

fn package(root: &Path, version: &str, arch: &str, binary: &[u8]) -> io::Result<Vec<u8>> {
    let control = include_str!("../control.in")
        .replace("@VERSION@", version)
        .replace("@ARCH@", arch);
    let controls = [
        ("control", 0o644, control.as_bytes()),
        ("conffiles", 0o644, &include_bytes!("../conffiles")[..]),
        ("postinst", 0o755, &include_bytes!("../postinst")[..]),
        ("prerm", 0o755, &include_bytes!("../prerm")[..]),
        ("postrm", 0o755, &include_bytes!("../postrm")[..]),
    ];
    let control = archive::tar(&controls.map(|(name, mode, data)| Entry {
        name,
        mode,
        directory: false,
        data,
    }))?;
    let unit = fs::read_to_string(root.join("contrib/rs-l2tpd.service.in"))?
        .replace("@BINARY@", "/usr/sbin/rs-l2tpd")
        .into_bytes();
    let mut files = vec![
        ("usr/sbin/rs-l2tpd", 0o755, binary.to_vec()),
        ("lib/systemd/system/rs-l2tpd.service", 0o644, unit),
        (
            "etc/rs-l2tpd.toml",
            0o644,
            fs::read(root.join("contrib/rs-l2tpd.toml"))?,
        ),
    ];
    for file in [
        "README.md",
        "LICENSE-APACHE",
        "LICENSE-MPL",
        "docs/installation.md",
    ] {
        let name = Path::new(file).file_name().unwrap().to_str().unwrap();
        files.push((
            match name {
                "README.md" => "usr/share/doc/rs-l2tpd/README.md",
                "LICENSE-APACHE" => "usr/share/doc/rs-l2tpd/LICENSE-APACHE",
                "LICENSE-MPL" => "usr/share/doc/rs-l2tpd/LICENSE-MPL",
                _ => "usr/share/doc/rs-l2tpd/installation.md",
            },
            0o644,
            fs::read(root.join(file))?,
        ));
    }
    let mut entries: Vec<_> = [
        "usr/",
        "usr/sbin/",
        "usr/share/",
        "usr/share/doc/",
        "usr/share/doc/rs-l2tpd/",
        "lib/",
        "lib/systemd/",
        "lib/systemd/system/",
        "etc/",
        "etc/rs-l2tpd.toml.d/",
    ]
    .into_iter()
    .map(|name| Entry {
        name,
        mode: 0o755,
        directory: true,
        data: &[],
    })
    .collect();
    entries.extend(files.iter().map(|(name, mode, data)| Entry {
        name,
        mode: *mode,
        directory: false,
        data,
    }));
    Ok(archive::deb(&control, &archive::tar(&entries)?))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn run(args: Vec<OsString>) -> io::Result<()> {
    if let [flag, binary, output] = args.as_slice()
        && flag == "--tar"
    {
        let data = fs::read(binary)?;
        let tar = archive::tar(&[Entry {
            name: "rs-l2tpd",
            mode: 0o755,
            directory: false,
            data: &data,
        }])?;
        return write_atomic(Path::new(output), &tar);
    }
    if let [flag, path] = args.as_slice()
        && flag == "--list"
    {
        let bytes = fs::read(path)?;
        print!("{}", archive::list(&bytes)?);
        return Ok(());
    }
    let targets = match args.as_slice() {
        [] => &TARGETS[..],
        [flag, target] if flag == "--target" => TARGETS
            .iter()
            .find(|(name, _, _)| target == name)
            .map(std::slice::from_ref)
            .ok_or_else(|| {
                invalid("target must be x86_64-unknown-linux-musl or aarch64-unknown-linux-musl")
            })?,
        _ => {
            return Err(invalid(
                "usage: musl-deb [--target TARGET | --list PACKAGE | --tar BINARY OUTPUT]",
            ));
        }
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let manifest = fs::read_to_string(root.join("Cargo.toml"))?;
    let version = version(&manifest)?;
    for &(target, arch, machine) in targets {
        let binary = fs::read(build(root, target)?)?;
        elf::check(&binary, machine)?;
        let bytes = package(root, version, arch, &binary)?;
        let output = root.join(format!("rs-l2tpd_{version}-1_{arch}.deb"));
        write_atomic(&output, &bytes)?;
        println!("built {}", output.display());
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run(std::env::args_os().skip(1).collect()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("musl-deb: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_scoped_and_cannot_inject_control_fields() {
        assert_eq!(
            version("[package]\nname=\"test\"\nversion = \"0.2.0\"\n[dependencies]\nfoo=\"1\"")
                .unwrap(),
            "0.2.0"
        );
        for input in [
            "[dependencies]\nversion=\"2\"",
            "[package]\n[dependencies]\nversion=\"2\"",
            "[package]\nversion=\"1\\nDepends: bad\"",
            "[package]\nversion=\"../2\"",
            "[package]\nversion=\"\"",
        ] {
            assert!(version(input).is_err());
        }
    }

    #[test]
    fn package_has_unit_configuration_and_all_scripts() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let bytes = package(root, "0.2.0", "amd64", b"fixture").unwrap();
        assert_eq!(bytes, package(root, "0.2.0", "amd64", b"fixture").unwrap());
        let listing = archive::list(&bytes).unwrap();
        for name in [
            "control",
            "conffiles",
            "postinst",
            "prerm",
            "postrm",
            "usr/sbin/rs-l2tpd",
            "lib/systemd/system/rs-l2tpd.service",
            "etc/rs-l2tpd.toml",
            "etc/rs-l2tpd.toml.d/",
            "usr/share/doc/rs-l2tpd/LICENSE-MPL",
        ] {
            assert!(
                listing.lines().any(|l| l.ends_with(&format!(" {name}"))),
                "{name}"
            );
        }
        assert!(
            bytes
                .windows(29)
                .any(|w| w == b"ExecStart=/usr/sbin/rs-l2tpd ")
        );
        assert!(
            !include_str!("../control.in")
                .lines()
                .any(|line| line.starts_with("Depends:"))
        );
    }
}
