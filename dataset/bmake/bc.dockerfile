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
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 http://www.crufty.net/ftp/pub/sjg/bmake-20251111.tar.gz && \
    tar -xzf bmake-20251111.tar.gz && \
    rm bmake-20251111.tar.gz

WORKDIR /home/SVF-tools/bmake

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
RUN mkdir -p ~/bc && \
    extract-bc bmake && \
    mv bmake.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
