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
RUN echo "project: lzo" > /work/proj && \
    echo "version: 2.10" >> /work/proj && \
    echo "source: https://www.oberhumer.com/opensource/lzo/download/lzo-2.10.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.oberhumer.com/opensource/lzo/download/lzo-2.10.tar.gz && \
    tar -xzf lzo-2.10.tar.gz && \
    rm lzo-2.10.tar.gz && \
    cp -a lzo-2.10 build-fuzz && \
    cp -a lzo-2.10 build-cmplog && \
    cp -a lzo-2.10 build-cov && \
    cp -a lzo-2.10 build-uftrace && \
    rm -rf lzo-2.10

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

# Build lzopack example with afl-clang-lto
RUN cd examples && \
    afl-clang-lto -O2 -I. -I../include -I.. -static -Wl,--allow-multiple-definition \
        -o lzopack lzopack.c ../src/.libs/liblzo2.a

WORKDIR /work
RUN ln -s build-fuzz/examples/lzopack bin-fuzz && \
    /work/bin-fuzz || true  # lzopack requires arguments, just verify it exists

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Build lzopack CMPLOG version
RUN cd examples && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I. -I../include -I.. -static -Wl,--allow-multiple-definition \
        -o lzopack lzopack.c ../src/.libs/liblzo2.a

WORKDIR /work
RUN ln -s build-cmplog/examples/lzopack bin-cmplog && \
    /work/bin-cmplog || true  # lzopack requires arguments, just verify it exists

# Copy fuzzing resources
COPY lzo/fuzz/dict /work/dict
COPY lzo/fuzz/in /work/in
COPY lzo/fuzz/fuzz.sh /work/fuzz.sh
COPY lzo/fuzz/whatsup.sh /work/whatsup.sh
COPY lzo/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

# Build lzopack with cov instrumentation
RUN cd examples && \
    clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -I. -I../include -I.. \
        -static -Wl,--allow-multiple-definition \
        -o lzopack lzopack.c ../src/.libs/liblzo2.a

WORKDIR /work
RUN ln -s build-cov/examples/lzopack bin-cov && \
    (/work/bin-cov || true) && \
    rm -f *.profraw  # lzopack requires arguments, just verify it exists

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

# Build lzopack with uftrace instrumentation
RUN cd examples && \
    clang -g -O0 -pg -fno-omit-frame-pointer -I. -I../include -I.. \
        -pg -Wl,--allow-multiple-definition \
        -o lzopack lzopack.c ../src/.libs/liblzo2.a && \
    mkdir -p /work/install-uftrace/bin && \
    cp lzopack /work/install-uftrace/bin/

WORKDIR /work
RUN ln -s install-uftrace/bin/lzopack bin-uftrace && \
    (/work/bin-uftrace || true) && \
    rm -f gmon.out  # lzopack requires arguments, just verify it exists

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
