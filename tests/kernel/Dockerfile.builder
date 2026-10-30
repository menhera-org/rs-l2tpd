FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends build-essential flex bison bc libelf-dev libssl-dev && rm -rf /var/lib/apt/lists/*
