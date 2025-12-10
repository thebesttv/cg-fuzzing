FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract rsync v3.3.0
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://download.samba.org/pub/rsync/src/rsync-3.3.0.tar.gz && \
    tar -xzf rsync-3.3.0.tar.gz && \
    rm rsync-3.3.0.tar.gz

WORKDIR /src/rsync-3.3.0

# Build rsync with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-xxhash --disable-zstd --disable-lz4 --disable-openssl

RUN make -j$(nproc)

# Copy the rsync binary
RUN cp rsync /out/rsync

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf rsync-3.3.0 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://download.samba.org/pub/rsync/src/rsync-3.3.0.tar.gz && \
    tar -xzf rsync-3.3.0.tar.gz && \
    rm rsync-3.3.0.tar.gz

WORKDIR /src/rsync-3.3.0

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-xxhash --disable-zstd --disable-lz4 --disable-openssl

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Copy CMPLOG binary
RUN cp rsync /out/rsync.cmplog

# Copy fuzzing resources
COPY rsync/fuzz/dict /out/dict
COPY rsync/fuzz/in /out/in
COPY rsync/fuzz/fuzz.sh /out/fuzz.sh
COPY rsync/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/rsync /out/rsync.cmplog && \
    file /out/rsync && \
    /out/rsync --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing rsync'"]
