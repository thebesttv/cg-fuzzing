FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract lz4 v1.10.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: lz4" > /work/proj && \
    echo "version: 1.10.0" >> /work/proj && \
    echo "source: https://github.com/lz4/lz4/releases/download/v1.10.0/lz4-1.10.0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/lz4/lz4/releases/download/v1.10.0/lz4-1.10.0.tar.gz && \
    tar -xzf lz4-1.10.0.tar.gz && \
    mv lz4-1.10.0 build && \
    rm lz4-1.10.0.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build lz4 with WLLVM
# lz4 uses a simple Makefile
RUN make clean || true && \
    make -j$(nproc) \
    CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    lz4

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc lz4 && \
    mv lz4.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
