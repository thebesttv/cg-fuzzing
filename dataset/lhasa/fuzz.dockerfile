FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract lhasa v0.4.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/fragglet/lhasa/releases/download/v0.4.0/lhasa-0.4.0.tar.gz && \
    tar -xzf lhasa-0.4.0.tar.gz && \
    rm lhasa-0.4.0.tar.gz

WORKDIR /src/lhasa-0.4.0

# Build lha with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the lha binary
RUN cp src/lha /out/lha

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf lhasa-0.4.0 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/fragglet/lhasa/releases/download/v0.4.0/lhasa-0.4.0.tar.gz && \
    tar -xzf lhasa-0.4.0.tar.gz && \
    rm lhasa-0.4.0.tar.gz

WORKDIR /src/lhasa-0.4.0

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/lha /out/lha.cmplog

# Copy fuzzing resources
COPY lhasa/fuzz/dict /out/dict
COPY lhasa/fuzz/in /out/in
COPY lhasa/fuzz/fuzz.sh /out/fuzz.sh
COPY lhasa/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/lha /out/lha.cmplog && \
    file /out/lha && \
    /out/lha --help || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing lha'"]
