//! RPM v4 output; use rpm-rs for the format, checksums and cpio payload.
use rpm::{BuildConfig, CompressionWithLevel, Dependency, FileOptions, Package, PackageBuilder};
use std::{fs, path::Path};

pub fn version(version: &str) -> String {
    // RPM sorts prereleases with ~ and forbids hyphens in its Version field.
    version.replace('-', "~")
}

pub fn build(
    root: &Path,
    version: &str,
    arch: &str,
    binary: &[u8],
    docs: &[(&str, Vec<u8>)],
) -> Result<Vec<u8>, rpm::Error> {
    let mut package = PackageBuilder::new(
        "rs-l2tpd",
        &self::version(version),
        "Apache-2.0 OR MPL-2.0",
        arch,
        "Resilient Linux L2TPv3 Ethernet pseudowire daemon",
    );
    package
        .using_config(
            BuildConfig::v4()
                .source_date(0_u32)
                .compression(CompressionWithLevel::None),
        )
        .release("1")
        .url("https://github.com/menhera-org/rs-l2tpd")
        .description("Maintains tunnels across link, address and resolver changes.\nStatically linked with musl; includes a systemd unit.")
        .requires(Dependency::interp("/bin/sh"))
        .recommends(Dependency::any("systemd"))
        .post_install_script(include_str!("../rpm-postinst"))
        .pre_uninstall_script(include_str!("../rpm-prerm"))
        .post_uninstall_script(include_str!("../rpm-postrm"));
    package.with_file_contents(
        binary,
        FileOptions::new("/usr/sbin/rs-l2tpd").permissions(0o755),
    )?;
    let unit = fs::read_to_string(root.join("contrib/rs-l2tpd.service.in"))?
        .replace("@BINARY@", "/usr/sbin/rs-l2tpd");
    package.with_file_contents(
        unit,
        FileOptions::new("/usr/lib/systemd/system/rs-l2tpd.service").permissions(0o644),
    )?;
    package.with_file_contents(
        fs::read(root.join("contrib/rs-l2tpd.toml"))?,
        FileOptions::new("/etc/rs-l2tpd.toml")
            .permissions(0o644)
            .config()
            .noreplace(),
    )?;
    for path in ["/etc/rs-l2tpd.toml.d", "/usr/share/doc/rs-l2tpd"] {
        package.with_dir_entry(FileOptions::dir(path).permissions(0o755))?;
    }
    for (name, bytes) in docs {
        // Notices must also survive installations made with rpm --excludedocs.
        package.with_file_contents(
            bytes.as_slice(),
            FileOptions::new(format!("/usr/share/doc/rs-l2tpd/{name}")).permissions(0o644),
        )?;
    }
    let mut bytes = Vec::new();
    package.build()?.write(&mut bytes)?;
    Ok(bytes)
}

pub fn list(bytes: &[u8]) -> Result<String, rpm::Error> {
    let package = Package::parse(&mut &bytes[..])?;
    package.verify_digests()?;
    let mut listing = String::new();
    for file in package.metadata.get_file_entries()? {
        listing.push_str(&format!("{}\n", file.path().display()));
    }
    Ok(listing)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_rpms_keep_config_notices_and_lifecycle_scripts() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let docs: Vec<_> = crate::DOCUMENTS
            .iter()
            .map(|(name, _)| (*name, format!("notice {name}").into_bytes()))
            .collect();
        for arch in ["x86_64", "aarch64"] {
            let bytes = build(root, "0.2.0", arch, b"static ELF fixture", &docs).unwrap();
            assert_eq!(
                bytes,
                build(root, "0.2.0", arch, b"static ELF fixture", &docs).unwrap()
            );
            let package = Package::parse(&mut bytes.as_slice()).unwrap();
            package.verify_digests().unwrap();
            let metadata = &package.metadata;
            assert_eq!(metadata.get_name().unwrap(), "rs-l2tpd");
            assert_eq!(metadata.get_version().unwrap(), "0.2.0");
            assert_eq!(metadata.get_release().unwrap(), "1");
            assert_eq!(metadata.get_arch().unwrap(), arch);
            assert_eq!(metadata.get_build_time().unwrap(), 0);
            assert!(metadata.get_build_host().is_err());
            assert_eq!(
                metadata.get_post_install_script().unwrap().script,
                include_str!("../rpm-postinst")
            );
            assert_eq!(
                metadata.get_pre_uninstall_script().unwrap().script,
                include_str!("../rpm-prerm")
            );
            assert_eq!(
                metadata.get_post_uninstall_script().unwrap().script,
                include_str!("../rpm-postrm")
            );
            let files = package
                .files()
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(files.len(), docs.len() + 5);
            for file in &files {
                assert_eq!(file.metadata.user(), "root");
                assert_eq!(file.metadata.group(), "root");
                assert_eq!(file.metadata.modified_at(), rpm::Timestamp::from(0_u32));
                let path = file.metadata.path();
                let mode = if path == Path::new("/usr/sbin/rs-l2tpd")
                    || file.metadata.mode().file_type() == rpm::FileType::Dir
                {
                    0o755
                } else {
                    0o644
                };
                assert_eq!(file.metadata.mode().permissions(), mode, "{path:?}");
                assert!(!file.metadata.flags().contains(rpm::FileFlags::DOC));
            }
            let config = files
                .iter()
                .find(|f| f.metadata.path() == Path::new("/etc/rs-l2tpd.toml"))
                .unwrap();
            assert!(
                config
                    .metadata
                    .flags()
                    .contains(rpm::FileFlags::CONFIG | rpm::FileFlags::NOREPLACE)
            );
            assert_eq!(
                config.content().unwrap(),
                fs::read(root.join("contrib/rs-l2tpd.toml")).unwrap()
            );
            let daemon = files
                .iter()
                .find(|f| f.metadata.path() == Path::new("/usr/sbin/rs-l2tpd"))
                .unwrap();
            assert_eq!(daemon.content().unwrap(), b"static ELF fixture");
            for (name, data) in &docs {
                let path = format!("/usr/share/doc/rs-l2tpd/{name}");
                let notice = files
                    .iter()
                    .find(|f| f.metadata.path() == Path::new(&path))
                    .unwrap();
                assert_eq!(notice.content().unwrap(), data);
            }
            let listing = list(&bytes).unwrap();
            assert!(listing.contains("/usr/lib/systemd/system/rs-l2tpd.service\n"));
            assert!(!listing.contains("\n/lib/systemd"));
            let mut corrupt = bytes.clone();
            *corrupt.last_mut().unwrap() ^= 1;
            assert!(list(&corrupt).is_err());
            assert!(list(&bytes[..bytes.len() / 2]).is_err());
        }
        assert_eq!(version("0.2.0-rc.1"), "0.2.0~rc.1");
    }
}
