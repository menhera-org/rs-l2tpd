FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bc \
        bison \
        build-essential \
        flex \
        libelf-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*
