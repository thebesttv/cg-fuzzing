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
RUN echo "project: libunistring" > /work/proj && \
    echo "version: 1.2" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/libunistring/libunistring-1.2.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/libunistring/libunistring-1.2.tar.gz && \
    tar -xzf libunistring-1.2.tar.gz && \
    rm libunistring-1.2.tar.gz && \
    cp -a libunistring-1.2 build-fuzz && \
    cp -a libunistring-1.2 build-cmplog && \
    cp -a libunistring-1.2 build-cov && \
    cp -a libunistring-1.2 build-uftrace && \
    rm -rf libunistring-1.2

# Create test harness source
RUN echo '#include "config.h"' > /work/test_unistring.c && \
    echo '#include <unistr.h>' >> /work/test_unistring.c && \
    echo '#include <stdlib.h>' >> /work/test_unistring.c && \
    echo '#include <unistd.h>' >> /work/test_unistring.c && \
    echo '#include <fcntl.h>' >> /work/test_unistring.c && \
    echo 'int main(int argc, char **argv) {' >> /work/test_unistring.c && \
    echo '    if (argc < 2) return 1;' >> /work/test_unistring.c && \
    echo '    int fd = open(argv[1], O_RDONLY);' >> /work/test_unistring.c && \
    echo '    if (fd < 0) return 1;' >> /work/test_unistring.c && \
    echo '    uint8_t buf[1024];' >> /work/test_unistring.c && \
    echo '    ssize_t n = read(fd, buf, sizeof(buf));' >> /work/test_unistring.c && \
    echo '    close(fd);' >> /work/test_unistring.c && \
    echo '    if (n <= 0) return 1;' >> /work/test_unistring.c && \
    echo '    u8_check(buf, n);' >> /work/test_unistring.c && \
    echo '    return 0;' >> /work/test_unistring.c && \
    echo '}' >> /work/test_unistring.c

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

RUN afl-clang-lto -O2 /work/test_unistring.c -o test_unistring \
    -I. -I./lib lib/.libs/libunistring.a \
    -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-fuzz/test_unistring bin-fuzz && \
    /work/bin-fuzz /work/test_unistring.c || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 /work/test_unistring.c -o test_unistring \
    -I. -I./lib lib/.libs/libunistring.a \
    -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-cmplog/test_unistring bin-cmplog && \
    /work/bin-cmplog /work/test_unistring.c || true

# Copy fuzzing resources
COPY libunistring/fuzz/dict /work/dict
COPY libunistring/fuzz/in /work/in
COPY libunistring/fuzz/fuzz.sh /work/fuzz.sh
COPY libunistring/fuzz/whatsup.sh /work/whatsup.sh
COPY libunistring/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY libunistring/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY libunistring/fuzz/collect-branch.py /work/collect-branch.py
COPY libunistring/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY libunistring/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping /work/test_unistring.c -o test_unistring \
    -I. -I./lib lib/.libs/libunistring.a \
    -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-cov/test_unistring bin-cov && \
    /work/bin-cov /work/test_unistring.c || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

RUN clang -g -O0 -pg -fno-omit-frame-pointer /work/test_unistring.c -o test_unistring \
    -I. -I./lib lib/.libs/libunistring.a \
    -pg -Wl,--allow-multiple-definition && \
    mkdir -p /work/install-uftrace/bin && \
    cp test_unistring /work/install-uftrace/bin/

WORKDIR /work
RUN ln -s install-uftrace/bin/test_unistring bin-uftrace && \
    /work/bin-uftrace /work/test_unistring.c || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
