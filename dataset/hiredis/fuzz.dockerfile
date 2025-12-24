FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: hiredis" > /work/proj && \
    echo "version: 1.3.0" >> /work/proj && \
    echo "source: https://github.com/redis/hiredis/archive/refs/tags/v1.3.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/redis/hiredis/archive/refs/tags/v1.3.0.tar.gz && \
    tar -xzf v1.3.0.tar.gz && \
    rm v1.3.0.tar.gz && \
    cp -a hiredis-1.3.0 build-fuzz && \
    cp -a hiredis-1.3.0 build-cmplog && \
    cp -a hiredis-1.3.0 build-cov && \
    cp -a hiredis-1.3.0 build-uftrace && \
    rm -rf hiredis-1.3.0

# Create fuzzing harness in all build directories
RUN printf '%s\n' \
    '/* AFL++ fuzzer harness for hiredis RESP protocol reader */' \
    '#include <stdio.h>' \
    '#include <stdlib.h>' \
    '#include <string.h>' \
    '#include <unistd.h>' \
    '#include "hiredis.h"' \
    '#include "read.h"' \
    '' \
    'int main(int argc, char **argv) {' \
    '    char buf[65536];' \
    '    ssize_t len;' \
    '    redisReader *reader;' \
    '    void *reply;' \
    '' \
    '    if (argc > 1) {' \
    '        FILE *f = fopen(argv[1], "rb");' \
    '        if (!f) return 1;' \
    '        len = fread(buf, 1, sizeof(buf), f);' \
    '        fclose(f);' \
    '    } else {' \
    '        len = read(0, buf, sizeof(buf));' \
    '    }' \
    '' \
    '    if (len <= 0) return 0;' \
    '' \
    '    reader = redisReaderCreate();' \
    '    if (!reader) return 1;' \
    '' \
    '    if (redisReaderFeed(reader, buf, len) != REDIS_OK) {' \
    '        redisReaderFree(reader);' \
    '        return 0;' \
    '    }' \
    '' \
    '    while (redisReaderGetReply(reader, &reply) == REDIS_OK) {' \
    '        if (reply == NULL) break;' \
    '        freeReplyObject(reply);' \
    '    }' \
    '' \
    '    redisReaderFree(reader);' \
    '    return 0;' \
    '}' > /tmp/fuzz_reader.c

# Copy harness to all build directories
RUN for dir in build-fuzz build-cmplog build-cov build-uftrace; do \
      cp /tmp/fuzz_reader.c /work/$dir/; \
    done

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DDISABLE_TESTS=ON && \
    make -j$(nproc)

RUN afl-clang-lto \
    -O2 \
    -I. \
    -static -Wl,--allow-multiple-definition \
    fuzz_reader.c \
    build/libhiredis.a \
    -o fuzz_reader

WORKDIR /work
RUN ln -s build-fuzz/fuzz_reader bin-fuzz && \
    echo '*1\r\n$4\r\nPING\r\n' | /work/bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DDISABLE_TESTS=ON && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto \
    -O2 \
    -I. \
    -static -Wl,--allow-multiple-definition \
    fuzz_reader.c \
    build/libhiredis.a \
    -o fuzz_reader

WORKDIR /work
RUN ln -s build-cmplog/fuzz_reader bin-cmplog && \
    echo '*1\r\n$4\r\nPING\r\n' | /work/bin-cmplog

# Copy fuzzing resources
COPY hiredis/fuzz/dict /work/dict
COPY hiredis/fuzz/in /work/in
COPY hiredis/fuzz/fuzz.sh /work/fuzz.sh
COPY hiredis/fuzz/whatsup.sh /work/whatsup.sh
COPY hiredis/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY hiredis/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY hiredis/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DDISABLE_TESTS=ON && \
    make -j$(nproc)

RUN clang \
    -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -I. \
    -static -Wl,--allow-multiple-definition \
    fuzz_reader.c \
    build/libhiredis.a \
    -o fuzz_reader

WORKDIR /work
RUN ln -s build-cov/fuzz_reader bin-cov && \
    echo '*1\r\n$4\r\nPING\r\n' | /work/bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-pg -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DDISABLE_TESTS=ON && \
    make -j$(nproc)

RUN clang \
    -g -O0 -pg -fno-omit-frame-pointer \
    -I. \
    fuzz_reader.c \
    build/libhiredis.a \
    -Wl,--allow-multiple-definition \
    -o fuzz_reader

WORKDIR /work
RUN ln -s build-uftrace/fuzz_reader bin-uftrace && \
    echo '*1\r\n$4\r\nPING\r\n' | /work/bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
