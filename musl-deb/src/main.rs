//! Build static DEB and RPM daemon packages without distribution build tools.
mod archive;
mod elf;
mod rpm_package;

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

const DOCUMENTS: [(&str, &str); 7] = [
    ("README.md", "musl-deb/README.binary.md"),
    ("LICENSE-APACHE", "LICENSE-APACHE"),
    ("LICENSE-MPL", "LICENSE-MPL"),
    (
        "THIRD-PARTY-NOTICES.txt",
        "target/release-notices/THIRD-PARTY-NOTICES.txt",
    ),
    (
        "RUST-COPYRIGHT.html.gz",
        "target/release-notices/RUST-COPYRIGHT.html.gz",
    ),
    (
        "RUST-LICENSES.txt",
        "target/release-notices/RUST-LICENSES.txt",
    ),
    ("MUSL-COPYRIGHT", "target/release-notices/MUSL-COPYRIGHT"),
];

fn documentation(root: &Path) -> io::Result<Vec<(&'static str, Vec<u8>)>> {
    DOCUMENTS
        .iter()
        .map(|&(name, source)| Ok((name, fs::read(root.join(source))?)))
        .collect()
}

fn tarball(binary: &[u8], docs: &[(&str, Vec<u8>)]) -> io::Result<Vec<u8>> {
    let mut entries = vec![Entry {
        name: "rs-l2tpd",
        mode: 0o755,
        directory: false,
        data: binary,
    }];
    entries.extend(docs.iter().map(|(name, data)| Entry {
        name,
        mode: 0o644,
        directory: false,
        data,
    }));
    archive::tar(&entries)
}

fn package(
    root: &Path,
    version: &str,
    arch: &str,
    binary: &[u8],
    docs: &[(&str, Vec<u8>)],
) -> io::Result<Vec<u8>> {
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
    let files = [
        ("usr/sbin/rs-l2tpd", 0o755, binary.to_vec()),
        ("lib/systemd/system/rs-l2tpd.service", 0o644, unit),
        (
            "etc/rs-l2tpd.toml",
            0o644,
            fs::read(root.join("contrib/rs-l2tpd.toml"))?,
        ),
    ];
    let doc_names: Vec<_> = docs
        .iter()
        .map(|(name, _)| format!("usr/share/doc/rs-l2tpd/{name}"))
        .collect();
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
    entries.extend(docs.iter().zip(&doc_names).map(|((_, data), name)| Entry {
        name,
        mode: 0o644,
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
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    if let [flag, binary, output] = args.as_slice()
        && flag == "--tar"
    {
        let data = fs::read(binary)?;
        let tar = tarball(&data, &documentation(root)?)?;
        return write_atomic(Path::new(output), &tar);
    }
    if let [flag, path] = args.as_slice()
        && flag == "--list"
    {
        let bytes = fs::read(path)?;
        let listing = if bytes.starts_with(b"!<arch>\n") {
            archive::list(&bytes)?
        } else {
            rpm_package::list(&bytes).map_err(io::Error::other)?
        };
        print!("{listing}");
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
    let manifest = fs::read_to_string(root.join("Cargo.toml"))?;
    let version = version(&manifest)?;
    for &(target, arch, machine) in targets {
        let binary = fs::read(build(root, target)?)?;
        elf::check(&binary, machine)?;
        let docs = documentation(root)?;
        let bytes = package(root, version, arch, &binary, &docs)?;
        let output = root.join(format!("rs-l2tpd_{version}-1_{arch}.deb"));
        write_atomic(&output, &bytes)?;
        println!("built {}", output.display());
        let rpm_arch = if arch == "amd64" { "x86_64" } else { "aarch64" };
        let bytes = rpm_package::build(root, version, rpm_arch, &binary, &docs)
            .map_err(io::Error::other)?;
        let rpm_version = rpm_package::version(version);
        let output = root.join(format!("rs-l2tpd-{rpm_version}-1.{rpm_arch}.rpm"));
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
        let docs: Vec<_> = DOCUMENTS
            .iter()
            .map(|&(name, source)| {
                (
                    name,
                    if source.starts_with("target/") {
                        b"notice fixture".to_vec()
                    } else {
                        fs::read(root.join(source)).unwrap()
                    },
                )
            })
            .collect();
        let bytes = package(root, "0.2.0", "amd64", b"fixture", &docs).unwrap();
        assert_eq!(
            bytes,
            package(root, "0.2.0", "amd64", b"fixture", &docs).unwrap()
        );
        let release = tarball(b"fixture", &docs).unwrap();
        for (name, contents) in &docs {
            let path = format!("usr/share/doc/rs-l2tpd/{name}");
            assert!(
                archive::list(&bytes)
                    .unwrap()
                    .lines()
                    .any(|line| line.ends_with(&format!(" {path}")))
            );
            assert!(
                release
                    .windows(name.len())
                    .any(|window| window == name.as_bytes())
            );
            assert!(
                release
                    .windows(contents.len())
                    .any(|window| window == contents)
            );
        }
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
        assert!(include_str!("../control.in").contains("Depends: init-system-helpers (>= 1.54)"));
    }
}
