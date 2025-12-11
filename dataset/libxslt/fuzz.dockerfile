FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libxml2-dev xz-utils liblzma-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libxslt v1.1.42 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://download.gnome.org/sources/libxslt/1.1/libxslt-1.1.42.tar.xz && \
    tar -xf libxslt-1.1.42.tar.xz && \
    rm libxslt-1.1.42.tar.xz

WORKDIR /src/libxslt-1.1.42

# Build xsltproc with afl-clang-lto for fuzzing
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --without-python --without-crypto

RUN make -j$(nproc)

# Copy the xsltproc binary
RUN cp xsltproc/xsltproc /out/xsltproc

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf libxslt-1.1.42 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://download.gnome.org/sources/libxslt/1.1/libxslt-1.1.42.tar.xz && \
    tar -xf libxslt-1.1.42.tar.xz && \
    rm libxslt-1.1.42.tar.xz

WORKDIR /src/libxslt-1.1.42

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --without-python --without-crypto

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Copy CMPLOG binary
RUN cp xsltproc/xsltproc /out/xsltproc.cmplog

# Copy fuzzing resources
COPY libxslt/fuzz/dict /out/dict
COPY libxslt/fuzz/in /out/in
COPY libxslt/fuzz/fuzz.sh /out/fuzz.sh
COPY libxslt/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/xsltproc /out/xsltproc.cmplog && \
    file /out/xsltproc

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing xsltproc'"]
