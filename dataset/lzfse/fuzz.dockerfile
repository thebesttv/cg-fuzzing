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
RUN echo "project: lzfse" > /work/proj && \
    echo "version: 1.0" >> /work/proj && \
    echo "source: https://github.com/lzfse/lzfse/archive/refs/tags/lzfse-1.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/lzfse/lzfse/archive/refs/tags/lzfse-1.0.tar.gz && \
    tar -xzf lzfse-1.0.tar.gz && \
    rm lzfse-1.0.tar.gz && \
    cp -a lzfse-lzfse-1.0 build-fuzz && \
    cp -a lzfse-lzfse-1.0 build-cmplog && \
    cp -a lzfse-lzfse-1.0 build-cov && \
    cp -a lzfse-lzfse-1.0 build-uftrace && \
    rm -rf lzfse-lzfse-1.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/build/lzfse bin-fuzz && \
    /work/bin-fuzz -h || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/build/lzfse bin-cmplog && \
    /work/bin-cmplog -h || true

# Copy fuzzing resources
COPY lzfse/fuzz/dict /work/dict
COPY lzfse/fuzz/in /work/in
COPY lzfse/fuzz/fuzz.sh /work/fuzz.sh
COPY lzfse/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/build/lzfse bin-cov && \
    /work/bin-cov -h || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-pg -Wl,--allow-multiple-definition" \
        -DCMAKE_INSTALL_PREFIX=/work/install-uftrace \
        -DBUILD_SHARED_LIBS=OFF && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/lzfse bin-uftrace && \
    /work/bin-uftrace -h || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
