FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract nnn v5.1

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: nnn" > /work/proj && \
    echo "version: 5.1" >> /work/proj && \
    echo "source: https://github.com/jarun/nnn/archive/refs/tags/v5.1.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/jarun/nnn/archive/refs/tags/v5.1.tar.gz && \
    tar -xzf v5.1.tar.gz && \
    mv v5.1 build && \
    rm v5.1.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc, ncurses for nnn, readline)
RUN apt-get update && \
    apt-get install -y file libncurses-dev libreadline-dev pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build nnn with WLLVM
# nnn uses a simple Makefile, we set CC and CFLAGS
RUN CC=wllvm \
    CFLAGS_OPTIMIZATION="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make strip -j$(nproc)

# Create bc directory and extract bitcode file
RUN mkdir -p /work/bc && \
    extract-bc nnn && \
    mv nnn.bc /work/bc/

# Verify that bc file was created
RUN ls -la /work/bc/
