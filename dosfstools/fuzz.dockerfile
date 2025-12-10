FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract dosfstools 4.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/dosfstools/dosfstools/releases/download/v4.2/dosfstools-4.2.tar.gz && \
    tar -xzf dosfstools-4.2.tar.gz && \
    rm dosfstools-4.2.tar.gz

WORKDIR /src/dosfstools-4.2

# Build dosfstools with afl-clang-lto
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Copy binaries to output
RUN cp src/fsck.fat /out/fsck.fat && \
    cp src/mkfs.fat /out/mkfs.fat && \
    cp src/fatlabel /out/fatlabel

# Build CMPLOG version
WORKDIR /src
RUN rm -rf dosfstools-4.2 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/dosfstools/dosfstools/releases/download/v4.2/dosfstools-4.2.tar.gz && \
    tar -xzf dosfstools-4.2.tar.gz && \
    rm dosfstools-4.2.tar.gz

WORKDIR /src/dosfstools-4.2

RUN CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Copy CMPLOG binaries
RUN cp src/fsck.fat /out/fsck.fat.cmplog

# Copy fuzzing resources
COPY dosfstools/fuzz/dict /out/dict
COPY dosfstools/fuzz/in /out/in
COPY dosfstools/fuzz/fuzz.sh /out/fuzz.sh
COPY dosfstools/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/fsck.fat /out/fsck.fat.cmplog && \
    file /out/fsck.fat && \
    /out/fsck.fat --help || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing dosfstools'"]
