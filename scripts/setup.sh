#!/bin/bash
set -euo pipefail

# Resolve the project root even when launched from another directory.
cd "$(dirname "$0")/.."

sudo apt-get update
sudo apt-get install -y \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    iproute2 \
    iperf3 \
    ethtool \
    python3-matplotlib

make
sudo python3 lab.py doctor
