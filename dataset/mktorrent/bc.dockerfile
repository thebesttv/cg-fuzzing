FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract mktorrent v1.1

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: mktorrent" > /work/proj && \
    echo "version: 1.1" >> /work/proj && \
    echo "source: https://github.com/pobrn/mktorrent/archive/refs/tags/v1.1.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/pobrn/mktorrent/archive/refs/tags/v1.1.tar.gz && \
    tar -xzf v1.1.tar.gz && \
    mv v1.1 build && \
    rm v1.1.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc, libssl-dev for crypto functions)
RUN apt-get update && \
    apt-get install -y file libssl-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build with WLLVM (static linking)
# mktorrent uses a Makefile, need to override CC
RUN make CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    USE_OPENSSL=1 \
    -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc mktorrent && \
    mv mktorrent.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
