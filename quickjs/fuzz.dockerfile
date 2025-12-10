FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract quickjs 2024-01-13 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://bellard.org/quickjs/quickjs-2024-01-13.tar.xz && \
    tar -xJf quickjs-2024-01-13.tar.xz && \
    rm quickjs-2024-01-13.tar.xz

WORKDIR /src/quickjs-2024-01-13

# Build quickjs with afl-clang-lto for fuzzing (main target binary)
RUN make CC=afl-clang-lto \
    CFLAGS="-O2 -D_GNU_SOURCE -DCONFIG_VERSION=\\\"2024-01-13\\\"" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    CONFIG_LTO= \
    CONFIG_BIGNUM= \
    qjs \
    -j$(nproc)

# Install the qjs binary
RUN cp qjs /out/qjs

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf quickjs-2024-01-13 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://bellard.org/quickjs/quickjs-2024-01-13.tar.xz && \
    tar -xJf quickjs-2024-01-13.tar.xz && \
    rm quickjs-2024-01-13.tar.xz

WORKDIR /src/quickjs-2024-01-13

RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    CFLAGS="-O2 -D_GNU_SOURCE -DCONFIG_VERSION=\\\"2024-01-13\\\"" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    CONFIG_LTO= \
    CONFIG_BIGNUM= \
    qjs \
    -j$(nproc)

# Install CMPLOG binary
RUN cp qjs /out/qjs.cmplog

# Copy fuzzing resources
COPY quickjs/fuzz/dict /out/dict
COPY quickjs/fuzz/in /out/in
COPY quickjs/fuzz/fuzz.sh /out/fuzz.sh
COPY quickjs/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/qjs /out/qjs.cmplog && \
    file /out/qjs && \
    /out/qjs --help || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing QuickJS'"]
