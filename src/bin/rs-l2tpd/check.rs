//! Read-only check mode (P3, O8).
use std::path::Path;
pub fn run(main: &Path, directory: &Path) -> u8 {
    let loaded = super::files::load(main, directory);
    let (config, problems) = loaded.partial.into_config_lenient();
    super::files::report(&problems, false);
    super::files::report_errors(&loaded.errors);
    match toml::to_string_pretty(&config) {
        Ok(text) => {
            use std::io::Write;
            if let Err(error) = std::io::stdout().lock().write_all(text.as_bytes()) {
                log::error!("check output: {error}");
                return 1;
            }
        }
        Err(error) => {
            log::error!("check rendering: {error}");
            return 1;
        }
    }
    u8::from(!problems.is_empty() || !loaded.errors.is_empty())
}
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use rs_l2tpd::config::PartialConfig;
    /// spec: O8 P3
    #[test]
    fn fixed_order_corrected_values_and_omitted_defaults() {
        let partial: PartialConfig = toml::from_str("[sessions.z]\ntunnel_name='a'\nsession_id=2\ninterface_name='l2tp0'\ncookie='00112233'\ninterface_hwaddr='bad'\n[tunnels.a]\ntunnel_id=1\nremote_addr='bad host'\n[resolvers.dns]\naddresses=['192.0.2.53']\n[host]\nfix_bindv6only=false").unwrap();
        let (config, problems) = partial.into_config_lenient();
        assert_eq!(problems.len(), 2);
        let rendered = toml::to_string_pretty(&config).unwrap();
        let tables = ["[host]", "[resolvers.dns]", "[tunnels.a]", "[sessions.z]"]
            .map(|s| rendered.find(s).unwrap());
        assert!(tables.windows(2).all(|w| w[0] < w[1]));
        assert!(!rendered.contains("peer_tunnel_id"));
        assert!(!rendered.contains("peer_session_id"));
        assert!(!rendered.contains("remote_addr"));
        assert!(!rendered.contains("interface_hwaddr"));
        assert!(rendered.contains("00112233"));
    }
}
