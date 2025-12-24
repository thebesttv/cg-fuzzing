FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake libsodium-dev pkg-config uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: minisign" > /work/proj && \
    echo "version: 0.11" >> /work/proj && \
    echo "source: https://github.com/jedisct1/minisign/archive/refs/tags/0.11.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/jedisct1/minisign/archive/refs/tags/0.11.tar.gz && \
    tar -xzf 0.11.tar.gz && \
    rm 0.11.tar.gz && \
    cp -a minisign-0.11 build-fuzz && \
    cp -a minisign-0.11 build-cmplog && \
    cp -a minisign-0.11 build-cov && \
    cp -a minisign-0.11 build-uftrace && \
    rm -rf minisign-0.11

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/build/minisign bin-fuzz && \
    /work/bin-fuzz --version || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DCMAKE_BUILD_TYPE=Release && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/build/minisign bin-cmplog && \
    /work/bin-cmplog --version || true

# Copy fuzzing resources
COPY minisign/fuzz/dict /work/dict
COPY minisign/fuzz/in /work/in
COPY minisign/fuzz/fuzz.sh /work/fuzz.sh
COPY minisign/fuzz/whatsup.sh /work/whatsup.sh
COPY minisign/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
        -DCMAKE_BUILD_TYPE=Debug && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/build/minisign bin-cov && \
    /work/bin-cov --version || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-pg -Wl,--allow-multiple-definition" \
        -DCMAKE_BUILD_TYPE=Debug && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/build/minisign bin-uftrace && \
    /work/bin-uftrace --version || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
