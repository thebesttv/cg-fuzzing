FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
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
RUN echo "project: jhead" > /work/proj && \
    echo "version: 3.08" >> /work/proj && \
    echo "source: https://github.com/Matthias-Wandel/jhead/archive/refs/tags/3.08.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/Matthias-Wandel/jhead/archive/refs/tags/3.08.tar.gz && \
    tar -xzf 3.08.tar.gz && \
    rm 3.08.tar.gz && \
    cp -a jhead-3.08 build-fuzz && \
    cp -a jhead-3.08 build-cmplog && \
    cp -a jhead-3.08 build-cov && \
    cp -a jhead-3.08 build-uftrace && \
    rm -rf jhead-3.08

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make clean 2>/dev/null || true && \
    make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

WORKDIR /work
RUN ln -s build-fuzz/jhead bin-fuzz && \
    /work/bin-fuzz -V

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN make clean 2>/dev/null || true && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

WORKDIR /work
RUN ln -s build-cmplog/jhead bin-cmplog && \
    /work/bin-cmplog -V

# Copy fuzzing resources
COPY jhead/fuzz/dict /work/dict
COPY jhead/fuzz/in /work/in
COPY jhead/fuzz/fuzz.sh /work/fuzz.sh
COPY jhead/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make clean 2>/dev/null || true && \
    make -j$(nproc) \
    CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition"

WORKDIR /work
RUN ln -s build-cov/jhead bin-cov && \
    /work/bin-cov -V && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make clean 2>/dev/null || true && \
    make -j$(nproc) \
    CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition"

WORKDIR /work
RUN ln -s build-uftrace/jhead bin-uftrace && \
    /work/bin-uftrace -V && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
