# Library APIs

[Documentation index](README.md)

Without default features, the crate pulls in neither `clap`, `toml`,
`env_logger` nor `serde`. The library does no standard I/O, no file I/O,
reads no configuration file and no environment variable, installs no
signal handler, writes no kernel tunable, and logs through the `log`
facade. It talks to the kernel only: sockets, netlink and `/proc`. The
system resolver is the libc's, which reads its own files.

```toml
[dependencies]
rs-l2tpd = { version = "0.2", default-features = false }
# Or, to deserialize configurations from any serde format:
rs-l2tpd = { version = "0.2", default-features = false, features = ["serde"] }
```

- `rs_l2tpd::config` holds configuration types, built in code or deserialized
  with serde; a `Config` is always valid. `PartialConfig::into_config_lenient`
  and `into_config_with_previous` implement the
  [configuration error-handling rules](configuration.md#mistakes) and
  return every problem.
- `rs_l2tpd::service::Service` provides the daemon's event loop without
  process management, for Tokio programs. `new` fails at once when the
  kernel interfaces cannot be opened, leaving the retry to the caller;
  `converge` applies the configuration and returns once every eligible
  entry exists, with the entries left out for identifier conflicts; `run`
  handles events, reloads and shutdown, and converges first when
  `converge` was not called.
- `rs_l2tpd::blocking::Service` provides a blocking API on a Tokio runtime
  of its own, usable without Tokio or inside another runtime. Dropping it,
  before or after `run`, shuts down in order and removes everything.
- `rs_l2tpd::runtime::Runtime` is the reconciler, for programs that drive
  the event loop themselves. Every `ControlEvent` it sends goes to
  `handle_event`, in order, which dispatches every variant, including ones
  added later; call `shutdown` before dropping it for an orderly teardown.
  The runtime never writes a kernel tunable itself: when the
  `net.ipv6.bindv6only` fix is needed it sends an event, and the program
  performs the write and reports the outcome.

Every type from another crate that appears in the API is re-exported next
to where it is used: `config::IpHost`, `config::FQDN`,
`config::L2tpIfName`, `config::L2tpIfNameExt`, `error::L2tpError` and
`runtime::mpsc`. Naming them therefore needs no additional dependency of
a matching version. Public enums are non-exhaustive.

Both services hand out a `Control` handle for requesting reloads,
restarts and shutdowns and reading the current configuration. The binary
drives it from `SIGHUP`, `SIGUSR2`, `SIGTERM` and `SIGINT`.

Shutdown requests persist even when the event queue is full.
`Control::reload_wait()` waits for room; `reload()` fails if the queue is
full. The reload callback may block: a shutdown does not wait for it. An
error from it keeps the previous configuration; a panic ends the service
with an error after everything was removed.
