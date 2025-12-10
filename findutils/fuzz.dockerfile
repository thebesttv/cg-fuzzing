FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract findutils v4.10.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/findutils/findutils-4.10.0.tar.xz && \
    tar -xJf findutils-4.10.0.tar.xz && \
    rm findutils-4.10.0.tar.xz

WORKDIR /src/findutils-4.10.0

# Build findutils with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the xargs binary (good for fuzzing as it processes input)
RUN cp xargs/xargs /out/xargs
RUN cp find/find /out/find

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf findutils-4.10.0 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/findutils/findutils-4.10.0.tar.xz && \
    tar -xJf findutils-4.10.0.tar.xz && \
    rm findutils-4.10.0.tar.xz

WORKDIR /src/findutils-4.10.0

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp xargs/xargs /out/xargs.cmplog

# Copy fuzzing resources
COPY findutils/fuzz/dict /out/dict
COPY findutils/fuzz/in /out/in
COPY findutils/fuzz/fuzz.sh /out/fuzz.sh
COPY findutils/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/xargs /out/xargs.cmplog && \
    file /out/xargs && \
    /out/xargs --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing xargs'"]
