FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: opus" > /work/proj && \
    echo "version: 1.5.2" >> /work/proj && \
    echo "source: https://github.com/xiph/opus/releases/download/v1.5.2/opus-1.5.2.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/xiph/opus/releases/download/v1.5.2/opus-1.5.2.tar.gz && \
    tar -xzf opus-1.5.2.tar.gz && \
    rm opus-1.5.2.tar.gz && \
    cp -a opus-1.5.2 build-fuzz && \
    cp -a opus-1.5.2 build-cmplog && \
    cp -a opus-1.5.2 build-cov && \
    cp -a opus-1.5.2 build-uftrace && \
    rm -rf opus-1.5.2

# Build fuzz binary with afl-clang-fast
WORKDIR /work/build-fuzz
RUN CC=afl-clang-fast \
    CFLAGS="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --disable-doc && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/opus_demo bin-fuzz

# Build cmplog binary with afl-clang-fast + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-fast \
    CFLAGS="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static --disable-doc && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/opus_demo bin-cmplog

# Copy fuzzing resources
COPY opus/fuzz/dict /work/dict
COPY opus/fuzz/in /work/in
COPY opus/fuzz/fuzz.sh /work/fuzz.sh
COPY opus/fuzz/whatsup.sh /work/whatsup.sh
COPY opus/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --disable-doc && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/opus_demo bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --disable-doc && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/opus_demo bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
