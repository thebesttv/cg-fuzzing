FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: c-blosc" > /work/proj && \
    echo "version: 1.21.6" >> /work/proj && \
    echo "source: https://github.com/Blosc/c-blosc/archive/refs/tags/v1.21.6.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/Blosc/c-blosc/archive/refs/tags/v1.21.6.tar.gz && \
    tar -xzf v1.21.6.tar.gz && \
    rm v1.21.6.tar.gz && \
    cp -a c-blosc-1.21.6 build-fuzz && \
    cp -a c-blosc-1.21.6 build-cmplog && \
    cp -a c-blosc-1.21.6 build-cov && \
    cp -a c-blosc-1.21.6 build-uftrace && \
    rm -rf c-blosc-1.21.6

# Copy harness source
COPY c-blosc/fuzz/harness/afl_decompress.c /work/afl_decompress.c

# Build fuzz library with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DBUILD_STATIC=ON \
        -DBUILD_SHARED=OFF \
        -DBUILD_TESTS=OFF \
        -DBUILD_FUZZERS=OFF \
        -DBUILD_BENCHMARKS=OFF && \
    make -j$(nproc)

# Compile fuzz harness
RUN afl-clang-lto -O2 -I/work/build-fuzz/blosc \
    /work/afl_decompress.c \
    -o /work/build-fuzz/blosc_decompress_fuzz \
    /work/build-fuzz/build/blosc/libblosc.a -lpthread

WORKDIR /work
RUN ln -s build-fuzz/blosc_decompress_fuzz bin-fuzz && \
    echo "fuzz binary built" && file /work/bin-fuzz

# Build cmplog library with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DBUILD_STATIC=ON \
        -DBUILD_SHARED=OFF \
        -DBUILD_TESTS=OFF \
        -DBUILD_FUZZERS=OFF \
        -DBUILD_BENCHMARKS=OFF && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Compile cmplog harness
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I/work/build-cmplog/blosc \
    /work/afl_decompress.c \
    -o /work/build-cmplog/blosc_decompress_fuzz \
    /work/build-cmplog/build/blosc/libblosc.a -lpthread

WORKDIR /work
RUN ln -s build-cmplog/blosc_decompress_fuzz bin-cmplog && \
    echo "cmplog binary built" && file /work/bin-cmplog

# Copy fuzzing resources
COPY c-blosc/fuzz/dict /work/dict
COPY c-blosc/fuzz/in /work/in
COPY c-blosc/fuzz/fuzz.sh /work/fuzz.sh
COPY c-blosc/fuzz/whatsup.sh /work/whatsup.sh

# Build cov library with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DBUILD_STATIC=ON \
        -DBUILD_SHARED=OFF \
        -DBUILD_TESTS=OFF \
        -DBUILD_FUZZERS=OFF \
        -DBUILD_BENCHMARKS=OFF && \
    make -j$(nproc)

# Compile cov harness
RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -I/work/build-cov/blosc \
    /work/afl_decompress.c \
    -o /work/build-cov/blosc_decompress_fuzz \
    /work/build-cov/build/blosc/libblosc.a -lpthread

WORKDIR /work
RUN ln -s build-cov/blosc_decompress_fuzz bin-cov && \
    echo "cov binary built" && file /work/bin-cov && \
    rm -f *.profraw

# Build uftrace library with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DBUILD_STATIC=ON \
        -DBUILD_SHARED=OFF \
        -DBUILD_TESTS=OFF \
        -DBUILD_FUZZERS=OFF \
        -DBUILD_BENCHMARKS=OFF && \
    make -j$(nproc)

# Compile uftrace harness
RUN clang -g -O0 -pg -fno-omit-frame-pointer \
    -I/work/build-uftrace/blosc \
    /work/afl_decompress.c \
    -o /work/build-uftrace/blosc_decompress_fuzz \
    /work/build-uftrace/build/blosc/libblosc.a -lpthread

WORKDIR /work
RUN ln -s build-uftrace/blosc_decompress_fuzz bin-uftrace && \
    echo "uftrace binary built" && file /work/bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
