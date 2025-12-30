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
RUN echo "project: monocypher" > /work/proj && \
    echo "version: 4.0.2" >> /work/proj && \
    echo "source: https://monocypher.org/download/monocypher-4.0.2.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://monocypher.org/download/monocypher-4.0.2.tar.gz && \
    tar -xzf monocypher-4.0.2.tar.gz && \
    rm monocypher-4.0.2.tar.gz && \
    cp -a monocypher-4.0.2 build-fuzz && \
    cp -a monocypher-4.0.2 build-cmplog && \
    cp -a monocypher-4.0.2 build-cov && \
    cp -a monocypher-4.0.2 build-uftrace && \
    rm -rf monocypher-4.0.2

# Create fuzzing harness for AFL builds
RUN printf '%s\n' \
    '#include <stdio.h>' \
    '#include <stdlib.h>' \
    '#include <string.h>' \
    '#include <stdint.h>' \
    '#include <unistd.h>' \
    '#include "src/monocypher.h"' \
    '' \
    '__AFL_FUZZ_INIT();' \
    '' \
    'int main() {' \
    '    __AFL_INIT();' \
    '    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;' \
    '    while (__AFL_LOOP(10000)) {' \
    '        size_t len = __AFL_FUZZ_TESTCASE_LEN;' \
    '        if (len < 16 || len > 1024) continue;' \
    '        uint8_t hash[64];' \
    '        crypto_blake2b(hash, 64, buf, len);' \
    '        if (len >= 48) {' \
    '            uint8_t out[32], key[32], nonce[16];' \
    '            memcpy(key, buf, 32);' \
    '            memcpy(nonce, buf + 32, 16);' \
    '            crypto_chacha20_h(out, key, nonce);' \
    '        }' \
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
    '#include "src/monocypher.h"' \
    '' \
    'int main() {' \
    '    unsigned char buf[1024];' \
    '    ssize_t len = read(0, buf, sizeof(buf));' \
    '    if (len < 16) return 0;' \
    '    uint8_t hash[64];' \
    '    crypto_blake2b(hash, 64, buf, len);' \
    '    if (len >= 48) {' \
    '        uint8_t out[32], key[32], nonce[16];' \
    '        memcpy(key, buf, 32);' \
    '        memcpy(nonce, buf + 32, 16);' \
    '        crypto_chacha20_h(out, key, nonce);' \
    '    }' \
    '    return 0;' \
    '}' \
    > /work/simple_harness.c

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN afl-clang-lto -O2 -c src/monocypher.c -o monocypher.o && \
    ar rcs libmonocypher.a monocypher.o

WORKDIR /work
RUN afl-clang-lto -O2 \
    -I build-fuzz \
    fuzz_harness.c \
    build-fuzz/libmonocypher.a \
    -static -Wl,--allow-multiple-definition \
    -o bin-fuzz && \
    echo "test" | /work/bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -c src/monocypher.c -o monocypher.o && \
    ar rcs libmonocypher.a monocypher.o

WORKDIR /work
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 \
    -I build-cmplog \
    fuzz_harness.c \
    build-cmplog/libmonocypher.a \
    -static -Wl,--allow-multiple-definition \
    -o bin-cmplog && \
    echo "test" | /work/bin-cmplog

# Copy fuzzing resources
COPY monocypher/fuzz/dict /work/dict
COPY monocypher/fuzz/in /work/in
COPY monocypher/fuzz/fuzz.sh /work/fuzz.sh
COPY monocypher/fuzz/whatsup.sh /work/whatsup.sh
COPY monocypher/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY monocypher/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY monocypher/fuzz/collect-branch.py /work/collect-branch.py
COPY monocypher/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -c src/monocypher.c -o monocypher.o && \
    ar rcs libmonocypher.a monocypher.o

WORKDIR /work
RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -I build-cov \
    simple_harness.c \
    build-cov/libmonocypher.a \
    -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition \
    -o bin-cov && \
    echo "test" | /work/bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN clang -g -O0 -pg -fno-omit-frame-pointer -c src/monocypher.c -o monocypher.o && \
    ar rcs libmonocypher.a monocypher.o

WORKDIR /work
RUN clang -g -O0 -pg -fno-omit-frame-pointer \
    -I build-uftrace \
    simple_harness.c \
    build-uftrace/libmonocypher.a \
    -pg -Wl,--allow-multiple-definition \
    -o bin-uftrace && \
    echo "test" | /work/bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
