FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget pkg-config uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: nghttp2" > /work/proj && \
    echo "version: 1.68.0" >> /work/proj && \
    echo "source: https://github.com/nghttp2/nghttp2/releases/download/v1.68.0/nghttp2-1.68.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/nghttp2/nghttp2/releases/download/v1.68.0/nghttp2-1.68.0.tar.gz && \
    tar -xzf nghttp2-1.68.0.tar.gz && \
    rm nghttp2-1.68.0.tar.gz && \
    cp -a nghttp2-1.68.0 build-fuzz && \
    cp -a nghttp2-1.68.0 build-cmplog && \
    cp -a nghttp2-1.68.0 build-cov && \
    cp -a nghttp2-1.68.0 build-uftrace && \
    rm -rf nghttp2-1.68.0

# Copy harness source
COPY nghttp2/hd_decode.c /work/hd_decode.c

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --enable-lib-only && \
    make -j$(nproc) && \
    afl-clang-lto -O2 -static -Wl,--allow-multiple-definition \
        -I. -Ilib/includes \
        /work/hd_decode.c lib/.libs/libnghttp2.a \
        -o /work/build-fuzz/hd_decode

WORKDIR /work
RUN ln -s build-fuzz/hd_decode bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static --enable-lib-only && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -static -Wl,--allow-multiple-definition \
        -I. -Ilib/includes \
        /work/hd_decode.c lib/.libs/libnghttp2.a \
        -o /work/build-cmplog/hd_decode

WORKDIR /work
RUN ln -s build-cmplog/hd_decode bin-cmplog

# Copy fuzzing resources
COPY nghttp2/fuzz/dict /work/dict
COPY nghttp2/fuzz/in /work/in
COPY nghttp2/fuzz/fuzz.sh /work/fuzz.sh
COPY nghttp2/fuzz/whatsup.sh /work/whatsup.sh
COPY nghttp2/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY nghttp2/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY nghttp2/fuzz/collect-branch.py /work/collect-branch.py
COPY nghttp2/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --enable-lib-only && \
    make -j$(nproc) && \
    clang -g -O0 -fprofile-instr-generate -fcoverage-mapping \
        -static -Wl,--allow-multiple-definition \
        -I. -Ilib/includes \
        /work/hd_decode.c lib/.libs/libnghttp2.a \
        -o /work/build-cov/hd_decode

WORKDIR /work
RUN ln -s build-cov/hd_decode bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --enable-lib-only && \
    make -j$(nproc) && \
    clang -g -O0 -pg -fno-omit-frame-pointer \
        -Wl,--allow-multiple-definition \
        -I. -Ilib/includes \
        /work/hd_decode.c lib/.libs/libnghttp2.a \
        -o /work/build-uftrace/hd_decode

WORKDIR /work
RUN ln -s build-uftrace/hd_decode bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
