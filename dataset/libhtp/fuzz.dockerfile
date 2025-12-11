FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool pkg-config zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libhtp v0.5.52 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/OISF/libhtp/archive/refs/tags/0.5.52.tar.gz && \
    tar -xzf 0.5.52.tar.gz && \
    rm 0.5.52.tar.gz

WORKDIR /src/libhtp-0.5.52

# Generate configure script
RUN ./autogen.sh

# Build with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)

# Build test_fuzz
RUN cd test && make test_fuzz

# Install the test_fuzz binary
RUN cp test/test_fuzz /out/test_fuzz

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf libhtp-0.5.52 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/OISF/libhtp/archive/refs/tags/0.5.52.tar.gz && \
    tar -xzf 0.5.52.tar.gz && \
    rm 0.5.52.tar.gz

WORKDIR /src/libhtp-0.5.52

RUN ./autogen.sh

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

RUN cd test && AFL_LLVM_CMPLOG=1 make test_fuzz

# Install CMPLOG binary
RUN cp test/test_fuzz /out/test_fuzz.cmplog

# Copy fuzzing resources
COPY libhtp/fuzz/dict /out/dict
COPY libhtp/fuzz/in /out/in
COPY libhtp/fuzz/fuzz.sh /out/fuzz.sh
COPY libhtp/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/test_fuzz /out/test_fuzz.cmplog && \
    file /out/test_fuzz

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libhtp'"]
