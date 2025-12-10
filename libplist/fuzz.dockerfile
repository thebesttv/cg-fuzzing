FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libplist 2.7.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/libimobiledevice/libplist/archive/refs/tags/2.7.0.tar.gz && \
    tar -xzf 2.7.0.tar.gz && \
    rm 2.7.0.tar.gz

WORKDIR /src/libplist-2.7.0

# Create version file
RUN echo "2.7.0" > .tarball-version

# Bootstrap the project
RUN NOCONFIGURE=1 ./autogen.sh

# Configure with afl-clang-lto and static linking
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --without-cython

# Add static flags to the Makefile for linking
RUN find . -name Makefile -exec sed -i 's/\(plistutil_LDADD = \)/\1-all-static /' {} \;

# Build libplist
RUN make -j$(nproc)

# Copy the plistutil binary
RUN cp tools/plistutil /out/plistutil

# Build CMPLOG version
WORKDIR /src
RUN rm -rf libplist-2.7.0 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/libimobiledevice/libplist/archive/refs/tags/2.7.0.tar.gz && \
    tar -xzf 2.7.0.tar.gz && \
    rm 2.7.0.tar.gz

WORKDIR /src/libplist-2.7.0

RUN echo "2.7.0" > .tarball-version

RUN NOCONFIGURE=1 ./autogen.sh

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static --without-cython

RUN find . -name Makefile -exec sed -i 's/\(plistutil_LDADD = \)/\1-all-static /' {} \;

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

RUN cp tools/plistutil /out/plistutil.cmplog

# Copy fuzzing resources
COPY libplist/fuzz/dict /out/dict
COPY libplist/fuzz/in /out/in
COPY libplist/fuzz/fuzz.sh /out/fuzz.sh
COPY libplist/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/plistutil /out/plistutil.cmplog && \
    file /out/plistutil && \
    /out/plistutil --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libplist'"]
