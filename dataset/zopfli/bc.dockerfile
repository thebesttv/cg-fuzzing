FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract zopfli v1.0.3

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: zopfli" > /work/proj && \
    echo "version: 1.0.3" >> /work/proj && \
    echo "source: https://github.com/google/zopfli/archive/refs/tags/zopfli-1.0.3.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/google/zopfli/archive/refs/tags/zopfli-1.0.3.tar.gz && \
    tar -xzf zopfli-1.0.3.tar.gz && \
    mv zopfli-1.0.3 build && \
    rm zopfli-1.0.3.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build zopfli with WLLVM
# zopfli uses a simple Makefile, override CC and flags
RUN make CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes -W -Wall -Wextra -ansi -pedantic -lm -Wno-unused-function" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    zopfli

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc zopfli && \
    mv zopfli.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
