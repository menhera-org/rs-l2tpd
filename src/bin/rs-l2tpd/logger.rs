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
