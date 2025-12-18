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
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/pobrn/mktorrent/archive/refs/tags/v1.1.tar.gz && \
    tar -xzf v1.1.tar.gz && \
    rm v1.1.tar.gz

WORKDIR /home/SVF-tools/mktorrent-1.1

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
RUN mkdir -p ~/bc && \
    extract-bc mktorrent && \
    mv mktorrent.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
