# Metadata fetch failure before the matrix

The first `tests/docker/run.sh matrix required` attempt stopped at its
initial HTTPS metadata request with `tls: IllegalParameter`. No kernel
guest or test ran, and no matrix result was produced. The retained revision
and command identify the attempt. The subsequent
[matrix record](../matrix-20261031T133318Z-3943822/README.md) used a successful
HTTPS client request with certificate verification enabled; it records
its own independent test results.
