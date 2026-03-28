// NOTE to packagers: patch these lines, or
// favorably override in environment variables
// to override configuration paths.
const DEFAULT_CONFIG_FILE_PATH: &'static str = "/etc/rs-l2tpd.toml";
const DEFAULT_CONFIG_DIR_PATH: &'static str = "/etc/rs-l2tpd.toml.d";

fn main() {
    println!("cargo:rerun-if-env-changed=CONFIG_FILE_PATH");
    println!("cargo:rerun-if-env-changed=CONFIG_DIR_PATH");
    println!("cargo:rerun-if-changed=build.rs");
    if let Ok(path) = std::env::var("CONFIG_FILE_PATH") {
        println!("cargo:rustc-env=CONFIG_FILE_PATH={path}");
    } else {
        println!("cargo:rustc-env=CONFIG_FILE_PATH={DEFAULT_CONFIG_FILE_PATH}");
    }
    if let Ok(path) = std::env::var("CONFIG_DIR_PATH") {
        println!("cargo:rustc-env=CONFIG_DIR_PATH={path}");
    } else {
        println!("cargo:rustc-env=CONFIG_DIR_PATH={DEFAULT_CONFIG_DIR_PATH}");
    }
}
