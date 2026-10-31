# Earlier supplied-unit check

The earlier unmodified all-feature musl root-systemd case passes on Ubuntu
`6.8.0-147-generic` in 31.14 seconds, with no drop-ins. It precedes the final
coverage-method changes. The parent record treats it as supplementary; the
later root-systemd folder contains the final unmodified sandbox check.
Neither individual pass resolves the separate staged-MAC determinism failure.
