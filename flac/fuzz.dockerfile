FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract flac v1.5.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/xiph/flac/releases/download/1.5.0/flac-1.5.0.tar.xz && \
    tar -xJf flac-1.5.0.tar.xz && \
    rm flac-1.5.0.tar.xz

WORKDIR /src/flac-1.5.0

# Build flac with afl-clang-fast for fuzzing (main target binary)
# We need to provide the alloc_check symbols that FLAC expects in fuzzing mode
# Create a simple C file with the required symbols
RUN echo 'int alloc_check_threshold = 2147483647, alloc_check_counter = 0, alloc_check_keep_failing = 0;' > /tmp/alloc_check.c && \
    afl-clang-fast -c /tmp/alloc_check.c -o /tmp/alloc_check.o

RUN CC=afl-clang-fast \
    CXX=afl-clang-fast++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition /tmp/alloc_check.o" \
    ./configure --disable-shared --enable-static --disable-ogg

RUN make -j$(nproc)

# Install the flac binary
RUN cp src/flac/flac /out/flac

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf flac-1.5.0 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/xiph/flac/releases/download/1.5.0/flac-1.5.0.tar.xz && \
    tar -xJf flac-1.5.0.tar.xz && \
    rm flac-1.5.0.tar.xz

WORKDIR /src/flac-1.5.0

RUN echo 'int alloc_check_threshold = 2147483647, alloc_check_counter = 0, alloc_check_keep_failing = 0;' > /tmp/alloc_check.c && \
    afl-clang-fast -c /tmp/alloc_check.c -o /tmp/alloc_check_cmplog.o

RUN CC=afl-clang-fast \
    CXX=afl-clang-fast++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition /tmp/alloc_check_cmplog.o" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static --disable-ogg

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/flac/flac /out/flac.cmplog

# Copy fuzzing resources
COPY flac/fuzz/dict /out/dict
COPY flac/fuzz/in /out/in
COPY flac/fuzz/fuzz.sh /out/fuzz.sh
COPY flac/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/flac /out/flac.cmplog && \
    file /out/flac && \
    /out/flac --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing flac'"]
