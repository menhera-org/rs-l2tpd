#!/bin/sh
# Pinned release inputs, shared by build-release.sh and package CI.
RELEASE_TOOLCHAIN=1.99.1
RELEASE_CROSS=0.2.5
RELEASE_X86_IMAGE=ghcr.io/cross-rs/x86_64-unknown-linux-musl@sha256:77db671d8356a64ae72a3e1415e63f547f26d374fbe3c4762c1cd36c7eac7b99
RELEASE_ARM_IMAGE=ghcr.io/cross-rs/aarch64-unknown-linux-musl@sha256:702154f52b2d8091671aa2c84d5582d849f949977228c735ff8462f93cc0e1e4
export RELEASE_TOOLCHAIN RELEASE_CROSS RELEASE_X86_IMAGE RELEASE_ARM_IMAGE
