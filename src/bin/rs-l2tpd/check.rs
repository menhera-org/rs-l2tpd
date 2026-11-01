//! Read-only check mode (P3, O8).
use std::path::Path;
pub fn run(main: &Path, directory: &Path) -> u8 {
    let loaded = super::files::load(main, directory);
    let (config, problems) = loaded.partial.into_config_lenient();
    super::files::report(&problems, false);
    super::files::report_errors(&loaded.errors);
    if let Err(error) = output(
        toml::to_string_pretty(&config),
        &mut std::io::stdout().lock(),
    ) {
        log::error!("{error}");
        return 1;
    }
    u8::from(!problems.is_empty() || !loaded.errors.is_empty())
}
fn output(
    rendered: Result<String, toml::ser::Error>,
    writer: &mut dyn std::io::Write,
) -> Result<(), String> {
    let text = rendered.map_err(|error| format!("check rendering: {error}"))?;
    writer
        .write_all(text.as_bytes())
        .map_err(|error| format!("check output: {error}"))
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

    /// spec: P3, O8, G1
    #[test]
    fn output_preserves_render_and_write_errors() {
        let mut bytes = b"untouched".to_vec();
        let rendered = toml::to_string_pretty(&[1u8]);
        let expected = format!("check rendering: {}", rendered.as_ref().unwrap_err());
        assert_eq!(super::output(rendered, &mut bytes), Err(expected));
        assert_eq!(bytes, b"untouched");
        bytes.clear();
        super::output(Ok("exact output\n".into()), &mut bytes).unwrap();
        assert_eq!(bytes, b"exact output\n");
        let mut full: &mut [u8] = &mut [];
        let expected = std::io::Write::write_all(&mut full, b"x").unwrap_err();
        assert_eq!(
            super::output(Ok("x".into()), &mut full),
            Err(format!("check output: {expected}"))
        );
    }
}
