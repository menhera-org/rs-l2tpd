ARG BASE
FROM $BASE
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends systemd udev dbus iproute2 procps && rm -rf /var/lib/apt/lists/*
