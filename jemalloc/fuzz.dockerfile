FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract jemalloc v5.3.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/jemalloc/jemalloc/releases/download/5.3.0/jemalloc-5.3.0.tar.bz2 && \
    tar -xjf jemalloc-5.3.0.tar.bz2 && \
    rm jemalloc-5.3.0.tar.bz2

WORKDIR /src/jemalloc-5.3.0

# Build jemalloc test with afl-clang-lto for fuzzing (main target binary)
# We'll build the malloc integration test as our fuzzing target
# afl-clang-lto provides collision-free instrumentation
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make build_lib_static -j$(nproc) && \
    make tests -j$(nproc)

# Install the malloc test binary (representative allocation test)
RUN cp test/integration/malloc /out/malloc-test

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf jemalloc-5.3.0 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/jemalloc/jemalloc/releases/download/5.3.0/jemalloc-5.3.0.tar.bz2 && \
    tar -xjf jemalloc-5.3.0.tar.bz2 && \
    rm jemalloc-5.3.0.tar.bz2

WORKDIR /src/jemalloc-5.3.0

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make build_lib_static -j$(nproc) && \
    AFL_LLVM_CMPLOG=1 make tests -j$(nproc)

# Install CMPLOG binary
RUN cp test/integration/malloc /out/malloc-test.cmplog

# Copy fuzzing resources
COPY jemalloc/fuzz/dict /out/dict
COPY jemalloc/fuzz/in /out/in
COPY jemalloc/fuzz/fuzz.sh /out/fuzz.sh
COPY jemalloc/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/malloc-test /out/malloc-test.cmplog && \
    file /out/malloc-test

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing jemalloc malloc test'"]
