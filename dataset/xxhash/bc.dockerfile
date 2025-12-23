FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract xxHash v0.8.3

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: xxhash" > /work/proj && \
    echo "version: 0.8.3" >> /work/proj && \
    echo "source: https://github.com/Cyan4973/xxHash/archive/refs/tags/v0.8.3.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/Cyan4973/xxHash/archive/refs/tags/v0.8.3.tar.gz && \
    tar -xzf v0.8.3.tar.gz && \
    mv v0.8.3 build && \
    rm v0.8.3.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build xxhsum with WLLVM
# xxHash uses a simple Makefile
RUN make clean || true && \
    make -j$(nproc) \
    CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    xxhsum

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc xxhsum && \
    mv xxhsum.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
