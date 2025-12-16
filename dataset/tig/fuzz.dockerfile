FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool libncurses-dev libreadline-dev pkg-config uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: tig" > /work/proj && \
    echo "version: 2.6.0" >> /work/proj && \
    echo "source: https://github.com/jonas/tig/releases/download/tig-2.6.0/tig-2.6.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/jonas/tig/releases/download/tig-2.6.0/tig-2.6.0.tar.gz && \
    tar -xzf tig-2.6.0.tar.gz && \
    rm tig-2.6.0.tar.gz && \
    cp -a tig-2.6.0 build-fuzz && \
    cp -a tig-2.6.0 build-cmplog && \
    cp -a tig-2.6.0 build-cov && \
    cp -a tig-2.6.0 build-uftrace && \
    rm -rf tig-2.6.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/tig bin-fuzz && \
    /work/bin-fuzz --version

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
RUN ln -s build-cmplog/src/tig bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY tig/fuzz/dict /work/dict
COPY tig/fuzz/in /work/in
COPY tig/fuzz/fuzz.sh /work/fuzz.sh
COPY tig/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/tig bin-cov && \
    /work/bin-cov --version && \
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
RUN ln -s build-uftrace/src/tig bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
