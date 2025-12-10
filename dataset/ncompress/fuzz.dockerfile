FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract ncompress 5.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/vapier/ncompress/archive/refs/tags/v5.0.tar.gz && \
    tar -xzf v5.0.tar.gz && \
    rm v5.0.tar.gz

WORKDIR /src/ncompress-5.0

# Build with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make -j$(nproc)

# Install the compress binary
RUN cp compress /out/compress

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf ncompress-5.0 && \
    wget https://github.com/vapier/ncompress/archive/refs/tags/v5.0.tar.gz && \
    tar -xzf v5.0.tar.gz && \
    rm v5.0.tar.gz

WORKDIR /src/ncompress-5.0

RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make -j$(nproc)

# Install CMPLOG binary
RUN cp compress /out/compress.cmplog

# Copy fuzzing resources
COPY dataset/ncompress/fuzz/dict /out/dict
COPY dataset/ncompress/fuzz/in /out/in
COPY dataset/ncompress/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/ncompress/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/compress /out/compress.cmplog && \
    file /out/compress && \
    /out/compress -V || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing ncompress'"]
