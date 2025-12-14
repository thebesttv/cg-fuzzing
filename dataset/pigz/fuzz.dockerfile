FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget zlib1g-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: pigz" > /work/proj && \
    echo "version: 2.8" >> /work/proj && \
    echo "source: https://github.com/madler/pigz/archive/refs/tags/v2.8.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/madler/pigz/archive/refs/tags/v2.8.tar.gz && \
    tar -xzf v2.8.tar.gz && \
    rm v2.8.tar.gz && \
    cp -a pigz-2.8 build-fuzz && \
    cp -a pigz-2.8 build-cmplog && \
    cp -a pigz-2.8 build-cov && \
    cp -a pigz-2.8 build-uftrace && \
    rm -rf pigz-2.8

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make clean || true && \
    make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

WORKDIR /work
RUN ln -s build-fuzz/pigz bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN make clean || true && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

WORKDIR /work
RUN ln -s build-cmplog/pigz bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY pigz/fuzz/dict /work/dict
COPY pigz/fuzz/in /work/in
COPY pigz/fuzz/fuzz.sh /work/fuzz.sh
COPY pigz/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make clean || true && \
    make -j$(nproc) \
    CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition"

WORKDIR /work
RUN ln -s build-cov/pigz bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make clean || true && \
    make -j$(nproc) \
    CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition"

WORKDIR /work
RUN ln -s build-uftrace/pigz bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
