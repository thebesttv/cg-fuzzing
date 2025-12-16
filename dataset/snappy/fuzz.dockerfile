FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake ninja-build uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: snappy" > /work/proj && \
    echo "version: 1.2.1" >> /work/proj && \
    echo "source: https://github.com/google/snappy/archive/refs/tags/1.2.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/google/snappy/archive/refs/tags/1.2.1.tar.gz && \
    tar -xzf 1.2.1.tar.gz && \
    rm 1.2.1.tar.gz && \
    cp -a snappy-1.2.1 build-fuzz && \
    cp -a snappy-1.2.1 build-cmplog && \
    cp -a snappy-1.2.1 build-cov && \
    cp -a snappy-1.2.1 build-uftrace && \
    rm -rf snappy-1.2.1

# Create fuzzing harness for AFL builds
RUN printf '%s\n' \
    '#include <stdio.h>' \
    '#include <stdlib.h>' \
    '#include <string.h>' \
    '#include <stdint.h>' \
    '#include <unistd.h>' \
    '#include <snappy-c.h>' \
    '' \
    '__AFL_FUZZ_INIT();' \
    '' \
    'int main() {' \
    '    __AFL_INIT();' \
    '    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;' \
    '    while (__AFL_LOOP(10000)) {' \
    '        size_t len = __AFL_FUZZ_TESTCASE_LEN;' \
    '        if (len < 1 || len > 1024*1024) continue;' \
    '        size_t compressed_len = snappy_max_compressed_length(len);' \
    '        char *compressed = (char*)malloc(compressed_len);' \
    '        snappy_status status = snappy_compress((const char*)buf, len, compressed, &compressed_len);' \
    '        if (status == SNAPPY_OK) {' \
    '            size_t uncompressed_len;' \
    '            if (snappy_uncompressed_length(compressed, compressed_len, &uncompressed_len) == SNAPPY_OK) {' \
    '                char *uncompressed = (char*)malloc(uncompressed_len);' \
    '                snappy_uncompress(compressed, compressed_len, uncompressed, &uncompressed_len);' \
    '                free(uncompressed);' \
    '            }' \
    '        }' \
    '        free(compressed);' \
    '    }' \
    '    return 0;' \
    '}' \
    > /work/fuzz_harness.c

# Create simple harness for coverage/uftrace builds (no AFL macros)
RUN printf '%s\n' \
    '#include <stdio.h>' \
    '#include <stdlib.h>' \
    '#include <string.h>' \
    '#include <stdint.h>' \
    '#include <unistd.h>' \
    '#include <snappy-c.h>' \
    '' \
    'int main() {' \
    '    unsigned char buf[1024*1024];' \
    '    ssize_t len = read(0, buf, sizeof(buf));' \
    '    if (len < 1) return 0;' \
    '    size_t compressed_len = snappy_max_compressed_length(len);' \
    '    char *compressed = (char*)malloc(compressed_len);' \
    '    snappy_status status = snappy_compress((const char*)buf, len, compressed, &compressed_len);' \
    '    if (status == SNAPPY_OK) {' \
    '        size_t uncompressed_len;' \
    '        if (snappy_uncompressed_length(compressed, compressed_len, &uncompressed_len) == SNAPPY_OK) {' \
    '            char *uncompressed = (char*)malloc(uncompressed_len);' \
    '            snappy_uncompress(compressed, compressed_len, uncompressed, &uncompressed_len);' \
    '            free(uncompressed);' \
    '        }' \
    '    }' \
    '    free(compressed);' \
    '    return 0;' \
    '}' \
    > /work/simple_harness.c

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_CXX_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DSNAPPY_BUILD_TESTS=OFF \
        -DSNAPPY_BUILD_BENCHMARKS=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN afl-clang-lto -O2 \
    -I build-fuzz -I build-fuzz/build \
    fuzz_harness.c \
    build-fuzz/build/libsnappy.a \
    -static -Wl,--allow-multiple-definition \
    -lstdc++ \
    -o bin-fuzz && \
    echo "test" | /work/bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_CXX_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DSNAPPY_BUILD_TESTS=OFF \
        -DSNAPPY_BUILD_BENCHMARKS=OFF && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 \
    -I build-cmplog -I build-cmplog/build \
    fuzz_harness.c \
    build-cmplog/build/libsnappy.a \
    -static -Wl,--allow-multiple-definition \
    -lstdc++ \
    -o bin-cmplog && \
    echo "test" | /work/bin-cmplog

# Copy fuzzing resources
COPY snappy/fuzz/dict /work/dict
COPY snappy/fuzz/in /work/in
COPY snappy/fuzz/fuzz.sh /work/fuzz.sh
COPY snappy/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_CXX_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DSNAPPY_BUILD_TESTS=OFF \
        -DSNAPPY_BUILD_BENCHMARKS=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -I build-cov -I build-cov/build \
    simple_harness.c \
    build-cov/build/libsnappy.a \
    -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition \
    -lstdc++ \
    -o bin-cov && \
    echo "test" | /work/bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_CXX_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-pg -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DSNAPPY_BUILD_TESTS=OFF \
        -DSNAPPY_BUILD_BENCHMARKS=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN clang -g -O0 -pg -fno-omit-frame-pointer \
    -I build-uftrace -I build-uftrace/build \
    simple_harness.c \
    build-uftrace/build/libsnappy.a \
    -pg -Wl,--allow-multiple-definition \
    -lstdc++ \
    -o bin-uftrace && \
    echo "test" | /work/bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
