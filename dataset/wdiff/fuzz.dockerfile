FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libncurses-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract wdiff 1.2.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/wdiff/wdiff-1.2.2.tar.gz && \
    tar -xzf wdiff-1.2.2.tar.gz && \
    rm wdiff-1.2.2.tar.gz

WORKDIR /src/wdiff-1.2.2

# Build wdiff with afl-clang-lto for fuzzing (main target binary)
# Use static linking for better reproducibility
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

# Build only the necessary parts (skip doc which requires makeinfo)
RUN make -C lib -j$(nproc) && \
    make -C po -j$(nproc) && \
    make -C src -j$(nproc)

# Install the wdiff binary
RUN cp src/wdiff /out/wdiff

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf wdiff-1.2.2 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/wdiff/wdiff-1.2.2.tar.gz && \
    tar -xzf wdiff-1.2.2.tar.gz && \
    rm wdiff-1.2.2.tar.gz

WORKDIR /src/wdiff-1.2.2

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -C lib -j$(nproc) && \
    AFL_LLVM_CMPLOG=1 make -C po -j$(nproc) && \
    AFL_LLVM_CMPLOG=1 make -C src -j$(nproc)

# Install CMPLOG binary
RUN cp src/wdiff /out/wdiff.cmplog

# Copy fuzzing resources
COPY wdiff/fuzz/dict /out/dict
COPY wdiff/fuzz/in /out/in
COPY wdiff/fuzz/fuzz.sh /out/fuzz.sh
COPY wdiff/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/wdiff /out/wdiff.cmplog && \
    file /out/wdiff && \
    /out/wdiff --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing wdiff'"]
