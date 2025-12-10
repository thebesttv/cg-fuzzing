FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget liblzma-dev libbz2-dev zlib1g-dev libzstd-dev liblz4-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libarchive 3.8.3 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/libarchive/libarchive/releases/download/v3.8.3/libarchive-3.8.3.tar.gz && \
    tar -xzf libarchive-3.8.3.tar.gz && \
    rm libarchive-3.8.3.tar.gz

WORKDIR /src/libarchive-3.8.3

# Build bsdtar with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static \
    --without-xml2 --without-expat --without-openssl \
    --enable-bsdtar=static --enable-bsdcpio=static

RUN make -j$(nproc)

# Install the bsdtar binary
RUN cp bsdtar /out/bsdtar

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf libarchive-3.8.3 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/libarchive/libarchive/releases/download/v3.8.3/libarchive-3.8.3.tar.gz && \
    tar -xzf libarchive-3.8.3.tar.gz && \
    rm libarchive-3.8.3.tar.gz

WORKDIR /src/libarchive-3.8.3

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static \
    --without-xml2 --without-expat --without-openssl \
    --enable-bsdtar=static --enable-bsdcpio=static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp bsdtar /out/bsdtar.cmplog

# Copy fuzzing resources
COPY libarchive/fuzz/dict /out/dict
COPY libarchive/fuzz/in /out/in
COPY libarchive/fuzz/fuzz.sh /out/fuzz.sh
COPY libarchive/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/bsdtar /out/bsdtar.cmplog && \
    file /out/bsdtar && \
    /out/bsdtar --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing bsdtar'"]
