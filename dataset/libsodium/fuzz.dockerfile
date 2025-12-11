FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libsodium v1.0.20 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/jedisct1/libsodium/releases/download/1.0.20-RELEASE/libsodium-1.0.20.tar.gz && \
    tar -xzf libsodium-1.0.20.tar.gz && \
    rm libsodium-1.0.20.tar.gz

WORKDIR /src/libsodium-1.0.20

# Build libsodium test with afl-clang-lto for fuzzing (main target binary)
# Use static linking
# afl-clang-lto provides collision-free instrumentation
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc) && make check -j$(nproc)

# Install a test binary (use aead_chacha20poly1305 as fuzzing target)
RUN cp test/default/aead_chacha20poly1305 /out/aead_chacha20poly1305

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf libsodium-1.0.20 && \
    wget https://github.com/jedisct1/libsodium/releases/download/1.0.20-RELEASE/libsodium-1.0.20.tar.gz && \
    tar -xzf libsodium-1.0.20.tar.gz && \
    rm libsodium-1.0.20.tar.gz

WORKDIR /src/libsodium-1.0.20

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc) && AFL_LLVM_CMPLOG=1 make check -j$(nproc)

# Install CMPLOG binary
RUN cp test/default/aead_chacha20poly1305 /out/aead_chacha20poly1305.cmplog

# Copy fuzzing resources
COPY libsodium/fuzz/dict /out/dict
COPY libsodium/fuzz/in /out/in
COPY libsodium/fuzz/fuzz.sh /out/fuzz.sh
COPY libsodium/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/aead_chacha20poly1305 /out/aead_chacha20poly1305.cmplog && \
    file /out/aead_chacha20poly1305

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libsodium'"]
