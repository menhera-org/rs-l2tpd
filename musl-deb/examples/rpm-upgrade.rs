//! Generate a consumer-test upgrade with changed defaults from an actual package.
use rpm::{BuildConfig, CompressionWithLevel, FileOptions, FileType, Package, PackageBuilder};
use std::{error::Error, path::Path};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: rpm-upgrade INPUT.rpm OUTPUT.rpm".into());
    }
    let source = Package::open(&args[0])?;
    source.verify_digests()?;
    let metadata = &source.metadata;
    let mut upgrade = PackageBuilder::new(
        metadata.get_name()?,
        metadata.get_version()?,
        metadata.get_license()?,
        metadata.get_arch()?,
        metadata.get_summary()?,
    );
    upgrade
        .using_config(
            BuildConfig::v4()
                .source_date(0_u32)
                .compression(CompressionWithLevel::None),
        )
        .release(format!("{}.test", metadata.get_release()?))
        .post_install_script(metadata.get_post_install_script()?)
        .pre_uninstall_script(metadata.get_pre_uninstall_script()?)
        .post_uninstall_script(metadata.get_post_uninstall_script()?);
    for file in source.files()? {
        let file = file?;
        let path = file.metadata.path();
        let permissions = file.metadata.mode().permissions();
        if file.metadata.mode().file_type() == FileType::Dir {
            upgrade.with_dir_entry(
                FileOptions::dir(path.to_string_lossy()).permissions(permissions),
            )?;
        } else {
            let mut options = FileOptions::new(path.to_string_lossy()).permissions(permissions);
            let mut data = file
                .content()
                .ok_or("missing fixture file content")?
                .to_vec();
            if path == Path::new("/etc/rs-l2tpd.toml") {
                options = options.config().noreplace();
                data.extend_from_slice(b"\n# changed defaults in the consumer upgrade fixture\n");
            }
            upgrade.with_file_contents(data, options)?;
        }
    }
    upgrade.build()?.write_file(&args[1])?;
    Ok(())
}
