FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget bison flex uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: cproto" > /work/proj && \
    echo "version: 4.7w" >> /work/proj && \
    echo "source: https://invisible-mirror.net/archives/cproto/cproto-4.7w.tgz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://invisible-mirror.net/archives/cproto/cproto-4.7w.tgz && \
    tar -xzf cproto-4.7w.tgz && \
    rm cproto-4.7w.tgz && \
    cp -a cproto-4.7w build-fuzz && \
    cp -a cproto-4.7w build-cmplog && \
    cp -a cproto-4.7w build-cov && \
    cp -a cproto-4.7w build-uftrace && \
    rm -rf cproto-4.7w

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/cproto bin-fuzz && \
    /work/bin-fuzz -V | head -3

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/cproto bin-cmplog && \
    /work/bin-cmplog -V | head -3

# Copy fuzzing resources
COPY cproto/fuzz/dict /work/dict
COPY cproto/fuzz/in /work/in
COPY cproto/fuzz/fuzz.sh /work/fuzz.sh
COPY cproto/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/cproto bin-cov && \
    /work/bin-cov -V | head -3 && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/cproto bin-uftrace && \
    /work/bin-uftrace -V | head -3 && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
