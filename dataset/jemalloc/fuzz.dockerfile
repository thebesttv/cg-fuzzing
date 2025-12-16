FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: jemalloc" > /work/proj && \
    echo "version: 5.3.0" >> /work/proj && \
    echo "source: https://github.com/jemalloc/jemalloc/releases/download/5.3.0/jemalloc-5.3.0.tar.bz2" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/jemalloc/jemalloc/releases/download/5.3.0/jemalloc-5.3.0.tar.bz2 && \
    tar -xjf jemalloc-5.3.0.tar.bz2 && \
    rm jemalloc-5.3.0.tar.bz2 && \
    cp -a jemalloc-5.3.0 build-fuzz && \
    cp -a jemalloc-5.3.0 build-cmplog && \
    cp -a jemalloc-5.3.0 build-cov && \
    cp -a jemalloc-5.3.0 build-uftrace && \
    rm -rf jemalloc-5.3.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make build_lib -j$(nproc) && \
    make tests -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/test/integration/malloc bin-fuzz && \
    LD_LIBRARY_PATH=/work/build-fuzz/lib /work/bin-fuzz --help || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make build_lib -j$(nproc) && \
    AFL_LLVM_CMPLOG=1 make tests -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/test/integration/malloc bin-cmplog && \
    LD_LIBRARY_PATH=/work/build-cmplog/lib /work/bin-cmplog --help || true

# Copy fuzzing resources
COPY jemalloc/fuzz/dict /work/dict
COPY jemalloc/fuzz/in /work/in
COPY jemalloc/fuzz/fuzz.sh /work/fuzz.sh
COPY jemalloc/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make build_lib -j$(nproc) && \
    make tests -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/test/integration/malloc bin-cov && \
    LD_LIBRARY_PATH=/work/build-cov/lib /work/bin-cov --help || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make build_lib -j$(nproc) && \
    make tests -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/test/integration/malloc bin-uftrace && \
    LD_LIBRARY_PATH=/work/build-uftrace/lib /work/bin-uftrace --help || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
