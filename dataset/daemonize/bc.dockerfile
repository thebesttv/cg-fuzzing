FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract daemonize v1.7.8
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/bmc/daemonize/archive/refs/tags/release-1.7.8.tar.gz && \
    tar -xzf release-1.7.8.tar.gz && \
    rm release-1.7.8.tar.gz

WORKDIR /home/SVF-tools/daemonize-release-1.7.8

# Install build dependencies (file for extract-bc, autotools)
RUN apt-get update && \
    apt-get install -y file autoconf automake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build daemonize with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc daemonize && \
    mv daemonize.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
