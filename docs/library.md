# Library APIs

[Documentation index](README.md)

Without default features, the crate pulls in neither `clap`, `toml`,
`env_logger` nor `serde`. It reads no configuration files, writes no
terminal output, installs no signal handlers and logs through the `log`
facade.

```toml
[dependencies]
rs-l2tpd = { version = "0.2", default-features = false }
# Or, to deserialize configurations from any serde format:
rs-l2tpd = { version = "0.2", default-features = false, features = ["serde"] }
```

- `rs_l2tpd::config` holds configuration types, built in code or deserialized
  with serde. `PartialConfig::into_config_lenient` and
  `into_config_with_previous` implement the
  [configuration error-handling rules](configuration.md#mistakes).
- `rs_l2tpd::service::Service` provides the daemon's event loop without
  process management, for Tokio programs.
- `rs_l2tpd::blocking::Service` provides a blocking API on a Tokio runtime
  of its own, usable without Tokio or inside another runtime.
- `rs_l2tpd::runtime::Runtime` is the reconciler, for programs that drive
  the event loop themselves.

Every type from another crate that appears in the API is re-exported next
to where it is used: `config::IpHost`, `config::FQDN`,
`config::L2tpIfName`, `config::L2tpIfNameExt`, `error::L2tpError` and
`runtime::mpsc`. Naming them therefore needs no additional dependency of
a matching version.

Both services hand out a `Control` handle for requesting reloads and
shutdowns and reading the current configuration. The binary drives it
from `SIGHUP`, `SIGTERM` and `SIGINT`.

Shutdown requests persist even when the event queue is full.
`Control::reload_wait()` waits for room; `reload()` fails if the queue is
full.
