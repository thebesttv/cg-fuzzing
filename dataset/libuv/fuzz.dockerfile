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
RUN echo "project: libuv" > /work/proj && \
    echo "version: 1.48.0" >> /work/proj && \
    echo "source: https://github.com/libuv/libuv/archive/refs/tags/v1.48.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/libuv/libuv/archive/refs/tags/v1.48.0.tar.gz && \
    tar -xzf v1.48.0.tar.gz && \
    rm v1.48.0.tar.gz && \
    cp -a libuv-1.48.0 build-fuzz && \
    cp -a libuv-1.48.0 build-cmplog && \
    cp -a libuv-1.48.0 build-cov && \
    cp -a libuv-1.48.0 build-uftrace && \
    rm -rf libuv-1.48.0

# Create test program source (used for all builds)
RUN cat > /work/test_uv.c <<'EOF'
#include <uv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) return 1;
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n <= 0) return 1;
    uv_loop_t *loop = uv_default_loop();
    if (!loop) return 1;
    uv_run(loop, UV_RUN_DEFAULT);
    uv_loop_close(loop);
    return 0;
}
EOF

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN ./autogen.sh && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc) && \
    afl-clang-lto -O2 \
    /work/test_uv.c -o test_uv \
    -I./include -I./src \
    .libs/libuv.a \
    -static -Wl,--allow-multiple-definition -lpthread

WORKDIR /work
RUN ln -s build-fuzz/test_uv bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN ./autogen.sh && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 \
    /work/test_uv.c -o test_uv \
    -I./include -I./src \
    .libs/libuv.a \
    -static -Wl,--allow-multiple-definition -lpthread

WORKDIR /work
RUN ln -s build-cmplog/test_uv bin-cmplog

# Copy fuzzing resources
COPY libuv/fuzz/dict /work/dict
COPY libuv/fuzz/in /work/in
COPY libuv/fuzz/fuzz.sh /work/fuzz.sh
COPY libuv/fuzz/whatsup.sh /work/whatsup.sh
COPY libuv/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY libuv/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY libuv/fuzz/collect-branch.py /work/collect-branch.py
COPY libuv/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN ./autogen.sh && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc) && \
    clang -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    /work/test_uv.c -o test_uv \
    -I./include -I./src \
    .libs/libuv.a \
    -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition -lpthread

WORKDIR /work
RUN ln -s build-cov/test_uv bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN ./autogen.sh && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install && \
    clang -g -O0 -pg -fno-omit-frame-pointer \
    /work/test_uv.c -o test_uv \
    -I./include -I./src \
    .libs/libuv.a \
    -pg -Wl,--allow-multiple-definition -lpthread

WORKDIR /work
RUN ln -s build-uftrace/test_uv bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
