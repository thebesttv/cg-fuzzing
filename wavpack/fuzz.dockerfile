FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download wavpack from GitHub (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/dbry/WavPack/archive/refs/tags/5.8.1.tar.gz && \
    tar -xzf 5.8.1.tar.gz && \
    rm 5.8.1.tar.gz

WORKDIR /src/WavPack-5.8.1

# Build wavpack with afl-clang-lto for fuzzing
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF \
        -DWAVPACK_BUILD_PROGRAMS=ON \
        -DWAVPACK_BUILD_DOCS=OFF

RUN cd build && make wvunpack -j$(nproc)

# Install the binaries
RUN cp build/wvunpack /out/wvunpack

# Build CMPLOG versions for better fuzzing
WORKDIR /src
RUN rm -rf WavPack-5.8.1 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/dbry/WavPack/archive/refs/tags/5.8.1.tar.gz && \
    tar -xzf 5.8.1.tar.gz && \
    rm 5.8.1.tar.gz

WORKDIR /src/WavPack-5.8.1

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF \
        -DWAVPACK_BUILD_PROGRAMS=ON \
        -DWAVPACK_BUILD_DOCS=OFF

RUN cd build && AFL_LLVM_CMPLOG=1 make wvunpack -j$(nproc)

# Install CMPLOG binaries
RUN cp build/wvunpack /out/wvunpack.cmplog

# Copy fuzzing resources
COPY wavpack/fuzz/dict /out/dict
COPY wavpack/fuzz/in /out/in
COPY wavpack/fuzz/fuzz.sh /out/fuzz.sh
COPY wavpack/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/wvunpack /out/wvunpack.cmplog && \
    file /out/wvunpack

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing wavpack'"]
