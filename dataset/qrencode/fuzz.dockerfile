FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libqrencode v4.1.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/fukuchi/libqrencode/archive/refs/tags/v4.1.1.tar.gz && \
    tar -xzf v4.1.1.tar.gz && \
    rm v4.1.1.tar.gz

WORKDIR /src/libqrencode-4.1.1

# Generate configure script
RUN autoreconf -i

# Build qrencode with afl-clang-lto for fuzzing (main target binary)
# Use static linking, enable CLI tools, disable png output
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --with-tools --without-png

RUN make -j$(nproc)

# Install the qrencode binary
RUN cp qrencode /out/qrencode

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf libqrencode-4.1.1 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/fukuchi/libqrencode/archive/refs/tags/v4.1.1.tar.gz && \
    tar -xzf v4.1.1.tar.gz && \
    rm v4.1.1.tar.gz

WORKDIR /src/libqrencode-4.1.1

RUN autoreconf -i

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static --with-tools --without-png

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp qrencode /out/qrencode.cmplog

# Copy fuzzing resources
COPY qrencode/fuzz/dict /out/dict
COPY qrencode/fuzz/in /out/in
COPY qrencode/fuzz/fuzz.sh /out/fuzz.sh
COPY qrencode/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/qrencode /out/qrencode.cmplog && \
    file /out/qrencode && \
    /out/qrencode --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing qrencode'"]
