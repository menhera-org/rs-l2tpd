// NOTE to packagers: patch these lines, or set the environment variables of
// the same names at build time, to change the built-in paths (spec C1, P10).
const DEFAULT_CONFIG_FILE_PATH: &str = "/etc/rs-l2tpd.toml";
const DEFAULT_CONFIG_DIR_PATH: &str = "/etc/rs-l2tpd.toml.d";
const DEFAULT_PID_FILE_PATH: &str = "/run/rs-l2tpd.pid";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    for (name, default) in [
        ("CONFIG_FILE_PATH", DEFAULT_CONFIG_FILE_PATH),
        ("CONFIG_DIR_PATH", DEFAULT_CONFIG_DIR_PATH),
        ("PID_FILE_PATH", DEFAULT_PID_FILE_PATH),
    ] {
        println!("cargo:rerun-if-env-changed={name}");
        let value = std::env::var(name).unwrap_or_else(|_| default.to_string());
        println!("cargo:rustc-env={name}={value}");
    }
}
