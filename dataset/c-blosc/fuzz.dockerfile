FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract c-blosc v1.21.6 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/Blosc/c-blosc/archive/refs/tags/v1.21.6.tar.gz && \
    tar -xzf v1.21.6.tar.gz && \
    rm v1.21.6.tar.gz

WORKDIR /src/c-blosc-1.21.6

# Build library with afl-clang-lto
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DBUILD_STATIC=ON \
        -DBUILD_SHARED=OFF \
        -DBUILD_TESTS=OFF \
        -DBUILD_FUZZERS=OFF \
        -DBUILD_BENCHMARKS=OFF

RUN cd build && make -j$(nproc)

# Copy harness and compile
COPY c-blosc/fuzz/harness/afl_decompress.c /src/afl_decompress.c
RUN afl-clang-lto -O2 -I/src/c-blosc-1.21.6/blosc \
    /src/afl_decompress.c \
    -o /out/blosc_decompress_fuzz \
    /src/c-blosc-1.21.6/build/blosc/libblosc.a -lpthread

# Build CMPLOG version
WORKDIR /src
RUN rm -rf c-blosc-1.21.6 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/Blosc/c-blosc/archive/refs/tags/v1.21.6.tar.gz && \
    tar -xzf v1.21.6.tar.gz && \
    rm v1.21.6.tar.gz

WORKDIR /src/c-blosc-1.21.6

RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DBUILD_STATIC=ON \
        -DBUILD_SHARED=OFF \
        -DBUILD_TESTS=OFF \
        -DBUILD_FUZZERS=OFF \
        -DBUILD_BENCHMARKS=OFF

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Compile CMPLOG harness
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I/src/c-blosc-1.21.6/blosc \
    /src/afl_decompress.c \
    -o /out/blosc_decompress_fuzz.cmplog \
    /src/c-blosc-1.21.6/build/blosc/libblosc.a -lpthread

# Copy fuzzing resources
COPY c-blosc/fuzz/dict /out/dict
COPY c-blosc/fuzz/in /out/in
COPY c-blosc/fuzz/fuzz.sh /out/fuzz.sh
COPY c-blosc/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/blosc_decompress_fuzz /out/blosc_decompress_fuzz.cmplog && \
    file /out/blosc_decompress_fuzz

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing c-blosc'"]
