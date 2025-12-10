FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libunistring-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libidn2 2.3.8 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/libidn/libidn2-2.3.8.tar.gz && \
    tar -xzf libidn2-2.3.8.tar.gz && \
    rm libidn2-2.3.8.tar.gz

WORKDIR /src/libidn2-2.3.8

# Build libidn2 with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)

# Install the idn2 binary
RUN cp src/idn2 /out/idn2

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf libidn2-2.3.8 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/libidn/libidn2-2.3.8.tar.gz && \
    tar -xzf libidn2-2.3.8.tar.gz && \
    rm libidn2-2.3.8.tar.gz

WORKDIR /src/libidn2-2.3.8

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/idn2 /out/idn2.cmplog

# Copy fuzzing resources
COPY libidn2/fuzz/dict /out/dict
COPY libidn2/fuzz/in /out/in
COPY libidn2/fuzz/fuzz.sh /out/fuzz.sh
COPY libidn2/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/idn2 /out/idn2.cmplog && \
    file /out/idn2 && \
    /out/idn2 --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libidn2'"]
