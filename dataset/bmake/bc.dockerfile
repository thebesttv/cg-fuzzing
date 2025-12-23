FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract bmake v20251111

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: bmake" > /work/proj && \
    echo "version: 20251111" >> /work/proj && \
    echo "source: http://www.crufty.net/ftp/pub/sjg/bmake-20251111.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 http://www.crufty.net/ftp/pub/sjg/bmake-20251111.tar.gz && \
    tar -xzf bmake-20251111.tar.gz && \
    mv bmake-20251111 build && \
    rm bmake-20251111.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

# Build bmake without running tests
# Use boot-strap to configure, then use make-bootstrap.sh
RUN ./boot-strap --prefix=/usr/local op=configure && \
    sh ./make-bootstrap.sh

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc bmake && \
    mv bmake.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
