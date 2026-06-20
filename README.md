# rs-l2tpd

Simple L2TPv3 daemon for Linux-based systems, written in Rust.

## Features

- L2TPv3 is handled in the kernel, so minimal overhead expected.
- Supports binding to specific VRFs or interfaces
- Supports FQDN-specified remote endpoints

## Early readiness during boot

This daemon binds its sockets to `::`, so it does not
need any networking for L2TPv3 interfaces to exist. It
does not need interfaces it binds to exist as well, and
it just creates sockets with no bind interfaces when
they are absent, and let the sockets bind to interfaces
when the interfaces appear. This is always possible as
the bind address is `::`. It also connects its sockets
to `100::` (a discard address) initially, and then to
the resolved addresses if FQDN was configured. Concrete
destination addresses are configured upfront always.

To signal the system of `rs-l2tpd`'s readiness (socket/
L2TPv3 interface existence), it has been modified to do
a double fork (daemonizing), and the parent only exits
on readiness of every interface configured.
`-p|--pidfile` option (defaults to `/run/rs-l2tpd.pid`)
is available. The startup always succeeds if the syntax
of the configs is correct. No failure on network
unavailability. SystemD integration files are modified
to match the new style.

This daemon intentionally does not depend on any
specific init system nor libc.
