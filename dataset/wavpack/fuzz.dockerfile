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
RUN echo "project: wavpack" > /work/proj && \
    echo "version: 5.8.1" >> /work/proj && \
    echo "source: https://github.com/dbry/WavPack/archive/refs/tags/5.8.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/dbry/WavPack/archive/refs/tags/5.8.1.tar.gz && \
    tar -xzf 5.8.1.tar.gz && \
    rm 5.8.1.tar.gz && \
    cp -a WavPack-5.8.1 build-fuzz && \
    cp -a WavPack-5.8.1 build-cmplog && \
    cp -a WavPack-5.8.1 build-cov && \
    cp -a WavPack-5.8.1 build-uftrace && \
    rm -rf WavPack-5.8.1

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF \
        -DWAVPACK_BUILD_PROGRAMS=ON \
        -DWAVPACK_BUILD_DOCS=OFF && \
    make wvunpack -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/build/wvunpack bin-fuzz && \
    /work/bin-fuzz --help || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF \
        -DWAVPACK_BUILD_PROGRAMS=ON \
        -DWAVPACK_BUILD_DOCS=OFF && \
    AFL_LLVM_CMPLOG=1 make wvunpack -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/build/wvunpack bin-cmplog && \
    /work/bin-cmplog --help || true

# Copy fuzzing resources
COPY wavpack/fuzz/dict /work/dict
COPY wavpack/fuzz/in /work/in
COPY wavpack/fuzz/fuzz.sh /work/fuzz.sh
COPY wavpack/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DBUILD_SHARED_LIBS=OFF \
        -DWAVPACK_BUILD_PROGRAMS=ON \
        -DWAVPACK_BUILD_DOCS=OFF && \
    make wvunpack -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/build/wvunpack bin-cov && \
    /work/bin-cov --help || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-pg -Wl,--allow-multiple-definition" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DBUILD_SHARED_LIBS=OFF \
        -DWAVPACK_BUILD_PROGRAMS=ON \
        -DWAVPACK_BUILD_DOCS=OFF && \
    make wvunpack -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/build/wvunpack bin-uftrace && \
    /work/bin-uftrace --help || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
