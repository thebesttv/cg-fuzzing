FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract rsync v3.3.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: rsync" > /work/proj && \
    echo "version: 3.3.0" >> /work/proj && \
    echo "source: https://download.samba.org/pub/rsync/src/rsync-3.3.0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://download.samba.org/pub/rsync/src/rsync-3.3.0.tar.gz && \
    tar -xzf rsync-3.3.0.tar.gz && \
    mv rsync-3.3.0 build && \
    rm rsync-3.3.0.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# Disable some features to simplify dependencies
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-xxhash --disable-zstd --disable-lz4 --disable-openssl

# Build rsync
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc rsync && \
    mv rsync.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
