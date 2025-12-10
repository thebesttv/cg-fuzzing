FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget yasm && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libvpx v1.14.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/webmproject/libvpx/archive/refs/tags/v1.14.1.tar.gz && \
    tar -xzf v1.14.1.tar.gz && \
    rm v1.14.1.tar.gz

WORKDIR /src/libvpx-1.14.1

# Build libvpx with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --enable-static --disable-shared --enable-vp9-highbitdepth

RUN make -j$(nproc)

# Copy vpxdec tool
RUN cp vpxdec /out/vpxdec

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf libvpx-1.14.1 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/webmproject/libvpx/archive/refs/tags/v1.14.1.tar.gz && \
    tar -xzf v1.14.1.tar.gz && \
    rm v1.14.1.tar.gz

WORKDIR /src/libvpx-1.14.1

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --enable-static --disable-shared --enable-vp9-highbitdepth

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Copy CMPLOG vpxdec tool
RUN cp vpxdec /out/vpxdec.cmplog

# Copy fuzzing resources
COPY libvpx/fuzz/dict /out/dict
COPY libvpx/fuzz/in /out/in
COPY libvpx/fuzz/fuzz.sh /out/fuzz.sh
COPY libvpx/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/vpxdec /out/vpxdec.cmplog && \
    file /out/vpxdec

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libvpx'"]
