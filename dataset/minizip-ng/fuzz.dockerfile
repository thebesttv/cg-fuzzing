FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake zlib1g-dev libbz2-dev liblzma-dev libzstd-dev libssl-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: minizip-ng" > /work/proj && \
    echo "version: 4.0.10" >> /work/proj && \
    echo "source: https://github.com/zlib-ng/minizip-ng/archive/refs/tags/4.0.10.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/zlib-ng/minizip-ng/archive/refs/tags/4.0.10.tar.gz && \
    tar -xzf 4.0.10.tar.gz && \
    rm 4.0.10.tar.gz && \
    cp -a minizip-ng-4.0.10 build-fuzz && \
    cp -a minizip-ng-4.0.10 build-cmplog && \
    cp -a minizip-ng-4.0.10 build-cov && \
    cp -a minizip-ng-4.0.10 build-uftrace && \
    rm -rf minizip-ng-4.0.10

# Copy harness source
COPY minizip-ng/fuzz/harness/afl_unzip.c /work/harness.c

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DMZ_BUILD_TESTS=OFF \
        -DMZ_BUILD_UNIT_TESTS=OFF \
        -DMZ_COMPAT=OFF \
        -DMZ_FETCH_LIBS=OFF && \
    make -j$(nproc)

RUN afl-clang-lto -O2 -I. \
    /work/harness.c \
    -o minizip_unzip_fuzz \
    build/libminizip-ng.a \
    -lz -lbz2 -llzma -lzstd -lssl -lcrypto -lpthread

WORKDIR /work
RUN ln -s build-fuzz/minizip_unzip_fuzz bin-fuzz && \
    /work/bin-fuzz || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DMZ_BUILD_TESTS=OFF \
        -DMZ_BUILD_UNIT_TESTS=OFF \
        -DMZ_COMPAT=OFF \
        -DMZ_FETCH_LIBS=OFF && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I. \
    /work/harness.c \
    -o minizip_unzip_fuzz \
    build/libminizip-ng.a \
    -lz -lbz2 -llzma -lzstd -lssl -lcrypto -lpthread

WORKDIR /work
RUN ln -s build-cmplog/minizip_unzip_fuzz bin-cmplog && \
    /work/bin-cmplog || true

# Copy fuzzing resources
COPY minizip-ng/fuzz/dict /work/dict
COPY minizip-ng/fuzz/in /work/in
COPY minizip-ng/fuzz/fuzz.sh /work/fuzz.sh
COPY minizip-ng/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DMZ_BUILD_TESTS=OFF \
        -DMZ_BUILD_UNIT_TESTS=OFF \
        -DMZ_COMPAT=OFF \
        -DMZ_FETCH_LIBS=OFF && \
    make -j$(nproc)

RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -I. \
    /work/harness.c \
    -o minizip_unzip_fuzz \
    build/libminizip-ng.a \
    -fprofile-instr-generate -fcoverage-mapping \
    -lz -lbz2 -llzma -lzstd -lssl -lcrypto -lpthread

WORKDIR /work
RUN ln -s build-cov/minizip_unzip_fuzz bin-cov && \
    /work/bin-cov || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DMZ_BUILD_TESTS=OFF \
        -DMZ_BUILD_UNIT_TESTS=OFF \
        -DMZ_COMPAT=OFF \
        -DMZ_FETCH_LIBS=OFF && \
    make -j$(nproc)

RUN clang -g -O0 -pg -fno-omit-frame-pointer -I. \
    /work/harness.c \
    -o minizip_unzip_fuzz \
    build/libminizip-ng.a \
    -pg \
    -lz -lbz2 -llzma -lzstd -lssl -lcrypto -lpthread

WORKDIR /work
RUN ln -s build-uftrace/minizip_unzip_fuzz bin-uftrace && \
    /work/bin-uftrace || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
