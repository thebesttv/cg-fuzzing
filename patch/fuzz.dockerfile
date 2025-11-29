FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract GNU patch 2.8 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/patch/patch-2.8.tar.gz && \
    tar -xzf patch-2.8.tar.gz && \
    rm patch-2.8.tar.gz

WORKDIR /src/patch-2.8

# Build patch with afl-clang-lto for fuzzing (main target binary)
# Use static linking
# afl-clang-lto provides collision-free instrumentation
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the patch binary
RUN cp src/patch /out/patch

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf patch-2.8 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/patch/patch-2.8.tar.gz && \
    tar -xzf patch-2.8.tar.gz && \
    rm patch-2.8.tar.gz

WORKDIR /src/patch-2.8

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/patch /out/patch.cmplog

# Copy fuzzing resources
COPY patch/fuzz/dict /out/dict
COPY patch/fuzz/in /out/in
COPY patch/fuzz/fuzz.sh /out/fuzz.sh
COPY patch/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/patch /out/patch.cmplog && \
    file /out/patch && \
    /out/patch --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing patch'"]
