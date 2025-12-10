FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract lz4 v1.10.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/lz4/lz4/releases/download/v1.10.0/lz4-1.10.0.tar.gz && \
    tar -xzf lz4-1.10.0.tar.gz && \
    rm lz4-1.10.0.tar.gz

WORKDIR /src/lz4-1.10.0

# Build with afl-clang-lto for fuzzing (main target binary)
# Use static linking
# afl-clang-lto provides collision-free instrumentation
RUN make clean || true && \
    make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    lz4

# Install the lz4 binary
RUN cp lz4 /out/lz4

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf lz4-1.10.0 && \
    wget https://github.com/lz4/lz4/releases/download/v1.10.0/lz4-1.10.0.tar.gz && \
    tar -xzf lz4-1.10.0.tar.gz && \
    rm lz4-1.10.0.tar.gz

WORKDIR /src/lz4-1.10.0

RUN make clean || true && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    lz4

# Install CMPLOG binary
RUN cp lz4 /out/lz4.cmplog

# Copy fuzzing resources
COPY dataset/lz4/fuzz/dict /out/dict
COPY dataset/lz4/fuzz/in /out/in
COPY dataset/lz4/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/lz4/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/lz4 /out/lz4.cmplog && \
    file /out/lz4 && \
    /out/lz4 --version || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing lz4'"]
