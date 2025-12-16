FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: xxhash" > /work/proj && \
    echo "version: 0.8.3" >> /work/proj && \
    echo "source: https://github.com/Cyan4973/xxHash/archive/refs/tags/v0.8.3.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/Cyan4973/xxHash/archive/refs/tags/v0.8.3.tar.gz && \
    tar -xzf v0.8.3.tar.gz && \
    rm v0.8.3.tar.gz && \
    cp -a xxHash-0.8.3 build-fuzz && \
    cp -a xxHash-0.8.3 build-cmplog && \
    cp -a xxHash-0.8.3 build-cov && \
    cp -a xxHash-0.8.3 build-uftrace && \
    rm -rf xxHash-0.8.3

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make clean || true && \
    make -j$(nproc) \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    xxhsum

WORKDIR /work
RUN ln -s build-fuzz/xxhsum bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN make clean || true && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    xxhsum

WORKDIR /work
RUN ln -s build-cmplog/xxhsum bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY xxhash/fuzz/dict /work/dict
COPY xxhash/fuzz/in /work/in
COPY xxhash/fuzz/fuzz.sh /work/fuzz.sh
COPY xxhash/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make clean || true && \
    make -j$(nproc) \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    xxhsum

WORKDIR /work
RUN ln -s build-cov/xxhsum bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make clean || true && \
    make -j$(nproc) \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    xxhsum

WORKDIR /work
RUN ln -s build-uftrace/xxhsum bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
