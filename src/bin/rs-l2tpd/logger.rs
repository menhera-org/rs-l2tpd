//! Standard-error logger (O1).
use log::{LevelFilter, Log, Metadata, Record};
struct Logger;
static LOGGER: Logger = Logger;
impl Log for Logger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= log::max_level()
    }
    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata()) {
            use std::io::Write;
            let _ = writeln!(
                std::io::stderr().lock(),
                "{} {}: {}",
                record.level(),
                record.target(),
                record
                    .args()
                    .to_string()
                    .replace('\n', "\\n")
                    .replace('\r', "\\r")
            );
        }
    }
    fn flush(&self) {}
}
pub fn init(verbose: bool) {
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(if verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    });
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// spec: O1, O2, O9
    #[test]
    fn direct_logging_filters_disabled_records_and_escapes_each_line() {
        const CHILD: &str = "RS_L2TPD_TEST_DIRECT_LOGGING";
        if std::env::var_os(CHILD).is_some() {
            init(true);
            LOGGER.log(
                &Record::builder()
                    .level(log::Level::Trace)
                    .target("probe")
                    .args(format_args!("filtered-record"))
                    .build(),
            );
            LOGGER.log(
                &Record::builder()
                    .level(log::Level::Info)
                    .target("probe")
                    .args(format_args!("first\nsecond\rthird"))
                    .build(),
            );
            LOGGER.flush();
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "logger::tests::direct_logging_filters_disabled_records_and_escapes_each_line",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(stderr, "INFO probe: first\\nsecond\\rthird\n");
    }
}
