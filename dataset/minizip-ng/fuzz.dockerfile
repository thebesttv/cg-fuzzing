FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake zlib1g-dev libbz2-dev liblzma-dev libzstd-dev libssl-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract minizip-ng v4.0.10 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/zlib-ng/minizip-ng/archive/refs/tags/4.0.10.tar.gz && \
    tar -xzf 4.0.10.tar.gz && \
    rm 4.0.10.tar.gz

WORKDIR /src/minizip-ng-4.0.10

# Build library with afl-clang-lto
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DMZ_BUILD_TESTS=OFF \
        -DMZ_BUILD_UNIT_TESTS=OFF \
        -DMZ_COMPAT=OFF \
        -DMZ_FETCH_LIBS=OFF

RUN cd build && make -j$(nproc)

# Copy harness and compile
COPY minizip-ng/fuzz/harness/afl_unzip.c /src/afl_unzip.c
RUN afl-clang-lto -O2 -I/src/minizip-ng-4.0.10 \
    /src/afl_unzip.c \
    -o /out/minizip_unzip_fuzz \
    /src/minizip-ng-4.0.10/build/libminizip-ng.a \
    -lz -lbz2 -llzma -lzstd -lssl -lcrypto -lpthread

# Build CMPLOG version
WORKDIR /src
RUN rm -rf minizip-ng-4.0.10 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/zlib-ng/minizip-ng/archive/refs/tags/4.0.10.tar.gz && \
    tar -xzf 4.0.10.tar.gz && \
    rm 4.0.10.tar.gz

WORKDIR /src/minizip-ng-4.0.10

RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DMZ_BUILD_TESTS=OFF \
        -DMZ_BUILD_UNIT_TESTS=OFF \
        -DMZ_COMPAT=OFF \
        -DMZ_FETCH_LIBS=OFF

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Compile CMPLOG harness
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I/src/minizip-ng-4.0.10 \
    /src/afl_unzip.c \
    -o /out/minizip_unzip_fuzz.cmplog \
    /src/minizip-ng-4.0.10/build/libminizip-ng.a \
    -lz -lbz2 -llzma -lzstd -lssl -lcrypto -lpthread

# Copy fuzzing resources
COPY minizip-ng/fuzz/dict /out/dict
COPY minizip-ng/fuzz/in /out/in
COPY minizip-ng/fuzz/fuzz.sh /out/fuzz.sh
COPY minizip-ng/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/minizip_unzip_fuzz /out/minizip_unzip_fuzz.cmplog && \
    file /out/minizip_unzip_fuzz

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing minizip-ng'"]
