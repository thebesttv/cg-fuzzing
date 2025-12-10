FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget texinfo zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract binutils v2.43.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://ftpmirror.gnu.org/gnu/binutils/binutils-2.43.1.tar.gz && \
    tar -xzf binutils-2.43.1.tar.gz && \
    rm binutils-2.43.1.tar.gz

WORKDIR /src/binutils-2.43.1

# Build binutils with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure \
        --disable-shared \
        --enable-static \
        --disable-werror \
        --disable-gdb \
        --disable-libdecnumber \
        --disable-readline \
        --disable-sim

RUN make -j$(nproc)

# Install the readelf binary (main tool for ELF analysis)
RUN cp binutils/readelf /out/readelf

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf binutils-2.43.1 && \
    wget https://ftpmirror.gnu.org/gnu/binutils/binutils-2.43.1.tar.gz && \
    tar -xzf binutils-2.43.1.tar.gz && \
    rm binutils-2.43.1.tar.gz

WORKDIR /src/binutils-2.43.1

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure \
        --disable-shared \
        --enable-static \
        --disable-werror \
        --disable-gdb \
        --disable-libdecnumber \
        --disable-readline \
        --disable-sim

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp binutils/readelf /out/readelf.cmplog

# Copy fuzzing resources
COPY dataset/binutils/fuzz/dict /out/dict
COPY dataset/binutils/fuzz/in /out/in
COPY dataset/binutils/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/binutils/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/readelf /out/readelf.cmplog && \
    file /out/readelf && \
    /out/readelf --version | head -3

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing binutils readelf'"]
