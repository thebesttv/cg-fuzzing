FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget zlib1g-dev liblzo2-dev liblz4-dev libzstd-dev liblzma-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract squashfs-tools 4.7.4 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/plougher/squashfs-tools/releases/download/4.7.4/squashfs-tools-4.7.4.tar.gz && \
    tar -xzf squashfs-tools-4.7.4.tar.gz && \
    rm squashfs-tools-4.7.4.tar.gz

WORKDIR /src/squashfs-tools-4.7.4/squashfs-tools

# Build unsquashfs with afl-clang-lto for fuzzing (main target binary)
# Use static linking
# afl-clang-lto provides collision-free instrumentation
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make -j$(nproc) unsquashfs

# Install the unsquashfs binary
RUN cp unsquashfs /out/unsquashfs

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf squashfs-tools-4.7.4 && \
    wget https://github.com/plougher/squashfs-tools/releases/download/4.7.4/squashfs-tools-4.7.4.tar.gz && \
    tar -xzf squashfs-tools-4.7.4.tar.gz && \
    rm squashfs-tools-4.7.4.tar.gz

WORKDIR /src/squashfs-tools-4.7.4/squashfs-tools

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make -j$(nproc) unsquashfs

# Install CMPLOG binary
RUN cp unsquashfs /out/unsquashfs.cmplog

# Copy fuzzing resources
COPY squashfs-tools/fuzz/dict /out/dict
COPY squashfs-tools/fuzz/in /out/in
COPY squashfs-tools/fuzz/fuzz.sh /out/fuzz.sh
COPY squashfs-tools/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/unsquashfs /out/unsquashfs.cmplog && \
    file /out/unsquashfs

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing squashfs-tools'"]
