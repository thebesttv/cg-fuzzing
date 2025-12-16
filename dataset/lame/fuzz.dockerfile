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
RUN echo "project: lame" > /work/proj && \
    echo "version: 3.100" >> /work/proj && \
    echo "source: https://downloads.sourceforge.net/lame/lame-3.100.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://downloads.sourceforge.net/lame/lame-3.100.tar.gz && \
    tar -xzf lame-3.100.tar.gz && \
    rm lame-3.100.tar.gz && \
    cp -a lame-3.100 build-fuzz && \
    cp -a lame-3.100 build-cmplog && \
    cp -a lame-3.100 build-cov && \
    cp -a lame-3.100 build-uftrace && \
    rm -rf lame-3.100

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/frontend/lame bin-fuzz && \
    /work/bin-fuzz --help

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/frontend/lame bin-cmplog && \
    /work/bin-cmplog --help

# Copy fuzzing resources
COPY lame/fuzz/dict /work/dict
COPY lame/fuzz/in /work/in
COPY lame/fuzz/fuzz.sh /work/fuzz.sh
COPY lame/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/frontend/lame bin-cov && \
    /work/bin-cov --help && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/frontend/lame bin-uftrace && \
    /work/bin-uftrace --help && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
