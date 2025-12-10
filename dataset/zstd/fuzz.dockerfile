FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract zstd v1.5.7 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz && \
    tar -xzf zstd-1.5.7.tar.gz && \
    rm zstd-1.5.7.tar.gz

WORKDIR /src/zstd-1.5.7

# Build zstd with afl-clang-lto for fuzzing (main target binary)
# Use static linking
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make -j$(nproc) zstd-release

# Install the zstd binary
RUN cp programs/zstd /out/zstd

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf zstd-1.5.7 && \
    wget https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz && \
    tar -xzf zstd-1.5.7.tar.gz && \
    rm zstd-1.5.7.tar.gz

WORKDIR /src/zstd-1.5.7

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make -j$(nproc) zstd-release

# Install CMPLOG binary
RUN cp programs/zstd /out/zstd.cmplog

# Copy fuzzing resources
COPY zstd/fuzz/dict /out/dict
COPY zstd/fuzz/in /out/in
COPY zstd/fuzz/fuzz.sh /out/fuzz.sh
COPY zstd/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/zstd /out/zstd.cmplog && \
    file /out/zstd && \
    /out/zstd --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing zstd'"]
