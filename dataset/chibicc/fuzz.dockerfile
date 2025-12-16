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
RUN echo "project: chibicc" > /work/proj && \
    echo "version: main" >> /work/proj && \
    echo "source: https://github.com/rui314/chibicc/archive/refs/heads/main.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/rui314/chibicc/archive/refs/heads/main.tar.gz -O chibicc.tar.gz && \
    tar -xzf chibicc.tar.gz && \
    rm chibicc.tar.gz && \
    cp -a chibicc-main build-fuzz && \
    cp -a chibicc-main build-cmplog && \
    cp -a chibicc-main build-cov && \
    cp -a chibicc-main build-uftrace && \
    rm -rf chibicc-main

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/chibicc bin-fuzz && \
    /work/bin-fuzz --help 2>&1 | head -5 || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/chibicc bin-cmplog && \
    /work/bin-cmplog --help 2>&1 | head -5 || true

# Copy fuzzing resources
COPY chibicc/fuzz/dict /work/dict
COPY chibicc/fuzz/in /work/in
COPY chibicc/fuzz/fuzz.sh /work/fuzz.sh
COPY chibicc/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/chibicc bin-cov && \
    /work/bin-cov --help 2>&1 | head -5 || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/chibicc bin-uftrace && \
    /work/bin-uftrace --help 2>&1 | head -5 || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
