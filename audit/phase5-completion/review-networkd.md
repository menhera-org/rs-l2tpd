# Live test: systemd-networkd / udev vs. create-then-rename of l2tpeth devices

Host kernel 6.8.0-147-generic (Ubuntu). Everything ran in disposable Docker
containers with `--network none`; the host network was never touched.
`dummy` and real `l2tpeth` (`ip l2tp add session ... name X`) devices were
both tested; they behaved identically in every case except one noted below.

Images (built from `Dockerfile` here, `apt-get install systemd udev dbus iproute2`):

| image | systemd |
|---|---|
| ubuntu:22.04 | 249 (249.11-0ubuntu3.23) |
| debian:12 | 252 (252.39-1~deb12u2) |
| ubuntu:24.04 | 255 (255.4-1ubuntu8.18) |
| ubuntu:26.04 | 259 (259.9-0ubuntu0.1) |

Environments:

- **container** = `docker run --cap-add ALL` (no `--privileged`): `/sys` is
  mounted `ro`, no udevd started. networkd logs
  `sd-device-monitor: The udev service seems not to be active, disabling the monitor`
  and never waits for udev. This models an unprivileged LXD/Incus system container.
- **native** = `docker run --privileged`: `/sys` rw, `systemd-udevd` running
  (debug log to file), `udevadm monitor` recording, stock `99-default.link`
  (`MACAddressPolicy=persistent`, `NamePolicy=keep ...`).

Procedure per test (script `networkd/run.sh`, args `container|native`):
`/etc/systemd/network/l2tp0.network` = `[Match] Name=l2tp0`, `[Network] Address=192.0.2.1/24`.
Test A: create `rsl2tp-tabc123`, sleep 1 s, `ip link set ... name l2tp0`, poll 5 s for the address.
Test B: create `l2tp0` directly. Then H2 MAC loops (native only), then add
`10-l2tp0.link` (`[Match] OriginalName=l2tp0`, `[Link] MACAddress=02:00:5e:00:53:01`),
`udevadm control --reload` (native), repeat A and B.

Raw outputs: `networkd/out-<image>-<env>.txt` in this directory.

## Results: does the `.network` get applied?

| systemd | env | A: create temp, sleep 1, rename | B: create as l2tp0 | key log line |
|---|---|---|---|---|
| 249 | container | **NOT applied** (dummy and l2tpeth) | applied in 1 s | `rsl2tp-tabc123: State changed: initialized -> unmanaged` then `Interface name change detected, renamed to l2tp0.` and nothing else |
| 252 | container | **NOT applied** | applied in 1 s | same as 249 |
| 255 | container | applied in 1 s | applied in 1 s | `renamed to l2tp0.` -> `l2tp0: found matching network ...` -> `l2tp0: Reconfiguring with /etc/systemd/network/l2tp0.network.` -> `State changed: unmanaged -> initialized` |
| 259 | container | applied in 1 s | applied in 1 s | `renamed to l2tp0.` -> `Found matching .network file` -> `Configuring with ...` -> `State changed: unmanaged -> initialized` |
| 249 | native | applied in 1 s | applied in 1 s | `renamed to l2tp0.` -> `l2tp0: udev initialized link` -> `State changed: unmanaged -> initialized` -> `found matching network` |
| 252 | native | applied in 1 s | applied in 1 s | same path: udev `move` uevent -> `l2tp0: udev initialized link` -> re-match |
| 255 | native | applied in 1 s | applied in 1 s | `Reconfiguring with ...` |
| 259 | native | applied in 1 s | applied in 1 s | `Configuring with ...` |

So on ≤ v252 the only thing that rescues the rename is udev's `move` uevent,
which networkd treats as "udev initialized link" and re-runs the `.network`
match. Without udev (container), v249/v252 only update the name table and the
link stays `unmanaged` forever. H3 `.link` files are irrelevant to this table
(results identical with and without the `.link` file).

## H2: MAC under 99-default.link MACAddressPolicy=persistent (native only)

Kernel gives dummy/l2tpeth a random MAC (`addr_assign_type=1`). udev's
`persistent` policy replaces it with a hash of (machine-id, sysname) and sets
`addr_assign_type=3`. Identical behaviour on 249, 252, 255, 259:

| scenario | run 1 | run 2 | run 3 | note |
|---|---|---|---|---|
| create `rsl2tp-t00000N` (distinct temp names), sleep 1, rename | different | different | different | v249: `a2:60:..`, `1a:9d:..`, `9e:0b:..`; udev on `add`: `rsl2tp-t000001: Applying persistent MAC address`; on `move`: `l2tp0: MAC address on the device already set by userspace.` |
| same temp name `rsl2tp-tabc123`, sleep 1, rename | X | X | - | identical both times: MAC is a function of the *temp* name |
| create `l2tp0` directly | Y | Y | Y | identical all 3 times (and equal across dummy and l2tpeth) |
| create temp + rename immediately (race) | temp-derived | temp-derived | temp-derived | 249/252/255: udev processed `add` before the rename all 9 times |
| same on 259 | **l2tp0-derived (= Y)** | temp-derived | temp-derived | run 1: `rsl2tp-t100001: MAC address on the device already matches policy "persistent"` then `l2tp0: addr_assign_type=1 ... Applying persistent MAC address: be:36:..` (= direct-create MAC) |

Raw example (v255): rename runs `16:88:2a:21:a4:37`, `0a:29:67:a6:a6:e4`,
`e6:d8:32:5f:4b:d4`; direct runs `d6:c9:f8:c3:41:5d` x3; race runs
`a2:db:1c:ab:7a:3b`, `d2:66:5b:82:50:f9`, `0a:02:17:aa:e9:38`.

Side observation (v255, native, l2tpeth, Test B): udev's persistent-MAC set
failed once with `Could not set ... MACAddress=/MACAddressPolicy= ... Device or
resource busy` and the device kept its kernel random MAC (`addr_assign_type=1`).
l2tp_eth refuses MAC changes while the interface is UP; networkd had already
brought it up. Not reproduced elsewhere; cause not investigated.

## H3: `.link` with OriginalName=l2tp0 MACAddress=02:00:5e:00:53:01

| systemd | env | A (rename) | B (direct) |
|---|---|---|---|
| 249/252/255/259 | native | **applied**: MAC `02:00:5e:00:53:01`, `ID_NET_LINK_FILE=/etc/systemd/network/10-l2tp0.link` (udev `add` applied 99-default.link under the temp name, then the `move` event matched `OriginalName=l2tp0` and applied the static MAC) | **applied**: `l2tp0: Config file /etc/systemd/network/10-l2tp0.link is applied`, `Applying static MAC address: 02:00:5e:00:53:01` |
| 249/252/255/259 | container | not applied (random kernel MAC, `addr_assign_type=1`) | not applied |

`.link` files are applied only by udev; without udev they do nothing in any version.

## Verdicts

- **H1: CONFIRMED.** Container (ro `/sys`, no udev): v249 and v252 never apply
  `[Match] Name=l2tp0` to a device that appeared as `rsl2tp-t...` and was
  renamed; v255 and v259 apply it after the rename (`Reconfiguring with ...`).
  Direct creation as `l2tp0` works on all four. On a native host with udev,
  all four versions apply it after the rename, via the udev `move` event.
- **H2: CONFIRMED** on all four versions. With the 1 s gap udev always wins the
  race: the MAC is derived from the temporary name (a fresh random name means a
  fresh MAC each time; reusing a temp name reuses the MAC), and the `move` event
  skips the policy (`MAC address on the device already set by userspace`).
  Direct creation as `l2tp0` yields the same MAC every time. In the immediate-
  rename race, udev still processed `add` first in 8 of 9 runs; in the one run
  where the rename came first (v259), the result was the stable l2tp0-derived MAC.
  Corollary: if the daemon sets a MAC itself (addr_assign_type becomes 3) before
  udev runs, udev's persistent policy is skipped and the MAC is whatever the
  daemon chose, independent of the name.
- **H3: CONFIRMED** (native, all versions, dummy and l2tpeth): the static MAC
  is applied on the `move` event after create-then-rename and on `add` after
  direct creation. Not applicable in the container case (no udev).

## Not tested / caveats

- Not a real LXD/Incus container: Docker with `--cap-add ALL` and the default
  read-only `/sys`, with networkd/udevd started by hand (no systemd PID 1, no
  D-Bus activation, but `dbus-daemon --system` was running).
- An earlier run with `--privileged` (rw `/sys`) and *no* udevd is worth noting
  although its outputs were overwritten: v252 and v259 networkd then waited
  forever for udev initialization (`link pending udev initialization...`) so
  even Test B failed, while v249 and v255 did not wait. A container with rw
  `/sys` but no udev is therefore a broken environment independent of the
  rename question.
- systemd v250, v251, v253, v254, v256-v258 were not run; the v252->v255
  boundary is consistent with the source reading (v253 introduced the
  reconfigure-on-rename), but the exact first version was not confirmed live.
- Native tests only had `dummy`/`l2tpeth` in a network namespace; real PCI/USB
  NICs with `ID_NET_NAME_*` properties (NamePolicy renaming) were not involved.
- The rename race (H2 last row) was run only 3 times per version.
- The v255 l2tpeth `EBUSY` MAC failure was observed once and not investigated.
