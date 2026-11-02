# K41 notification listener control

The foreign-namespace deletion test now requires a local deletion to reach
the same listener afterward. An absent foreign event can no longer pass
merely because the listener stopped working. Production code is unchanged.

All five required kernels pass the targeted musl guest profile. Ubuntu
6.8.0-147.147, Ubuntu 7.0.0-42.42, vanilla 6.8.12 and vanilla 7.0.14 announce
the foreign deletion; mainline 7.4-rc1 does not. Every run records
`local_control=1`. These observations agree with the existing K41 source
distinction; they do not change its contract.

The 7.4-rc1 failure control deliberately matches the wrong tunnel ID. Its
foreign-event absence check still passes, but the local control fails at
the intended assertion after five seconds. The final listener was restored.
The shipping patch then collapses a nested conditional as Clippy requires;
its short-circuit behavior is identical to the guest-qualified form.

`guest-source.patch` and `control-source.patch` identify the exact test and
temporary audit fixture for each run. Each positive boot also executes
65 ordinary CLI and three selected filesystem tests; the single K41 case
has its own result marker. The fixture is absent from the shipping patch.
These targeted profiles supplement the full matrix; no new Incus or
udev/networkd qualification is claimed.
