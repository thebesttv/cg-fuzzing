FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract BearSSL 0.6

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: bearssl" > /work/proj && \
    echo "version: 0.6" >> /work/proj && \
    echo "source: https://bearssl.org/bearssl-0.6.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://bearssl.org/bearssl-0.6.tar.gz && \
    tar -xzf bearssl-0.6.tar.gz && \
    mv bearssl-0.6 build && \
    rm bearssl-0.6.tar.gz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build BearSSL with WLLVM
# BearSSL uses a simple Makefile. Build only static lib and brssl tool
# Add -fPIC to avoid relocation issues
RUN make CC=wllvm CFLAGS="-g -O0 -Xclang -disable-llvm-passes -fPIC" LDFLAGS="-static -Wl,--allow-multiple-definition" lib -j$(nproc)
RUN make CC=wllvm CFLAGS="-g -O0 -Xclang -disable-llvm-passes -fPIC" LDFLAGS="-static -Wl,--allow-multiple-definition" tools -j$(nproc) || true
RUN make CC=wllvm CFLAGS="-g -O0 -Xclang -disable-llvm-passes -fPIC" LDFLAGS="-static -Wl,--allow-multiple-definition" build/brssl -j$(nproc)

# Create bc directory and extract bitcode files
# BearSSL provides: brssl (CLI tool for SSL operations)
RUN mkdir -p /work/bc && \
    extract-bc build/brssl && \
    mv build/brssl.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
