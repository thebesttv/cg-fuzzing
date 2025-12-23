FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
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
RUN echo "project: zlib-ng" > /work/proj && \
    echo "version: 2.3.1" >> /work/proj && \
    echo "source: https://github.com/zlib-ng/zlib-ng/archive/refs/tags/2.3.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/zlib-ng/zlib-ng/archive/refs/tags/2.3.1.tar.gz && \
    tar -xzf 2.3.1.tar.gz && \
    rm 2.3.1.tar.gz && \
    cp -a zlib-ng-2.3.1 build-fuzz && \
    cp -a zlib-ng-2.3.1 build-cmplog && \
    cp -a zlib-ng-2.3.1 build-cov && \
    cp -a zlib-ng-2.3.1 build-uftrace && \
    rm -rf zlib-ng-2.3.1

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DZLIB_COMPAT=ON \
        -DWITH_GTEST=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/build/minigzip bin-fuzz && \
    /work/bin-fuzz -h 2>&1 | head -3 || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DZLIB_COMPAT=ON \
        -DWITH_GTEST=OFF && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/build/minigzip bin-cmplog && \
    /work/bin-cmplog -h 2>&1 | head -3 || true

# Copy fuzzing resources
COPY zlib-ng/fuzz/dict /work/dict
COPY zlib-ng/fuzz/in /work/in
COPY zlib-ng/fuzz/fuzz.sh /work/fuzz.sh
COPY zlib-ng/fuzz/whatsup.sh /work/whatsup.sh
COPY zlib-ng/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DZLIB_COMPAT=ON \
        -DWITH_GTEST=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/build/minigzip bin-cov && \
    /work/bin-cov -h 2>&1 | head -3 || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-pg -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DZLIB_COMPAT=ON \
        -DWITH_GTEST=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/build/minigzip bin-uftrace && \
    /work/bin-uftrace -h 2>&1 | head -3 || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
