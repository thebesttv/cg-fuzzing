FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool bison flex git uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: jq-harness" > /work/proj && \
    echo "version: jq-1.8.1" >> /work/proj && \
    echo "source: git clone --depth 1 --branch jq-1.8.1 https://github.com/jqlang/jq.git" >> /work/proj && \
    echo "harness: tests/jq_fuzz_compile.c" >> /work/proj

# Download source once and extract to multiple build directories
RUN git clone --depth 1 --branch jq-1.8.1 https://github.com/jqlang/jq.git jq-1.8.1 && \
    cd jq-1.8.1 && git submodule init && git submodule update && cd .. && \
    cp -a jq-1.8.1 build-fuzz && \
    cp -a jq-1.8.1 build-cmplog && \
    cp -a jq-1.8.1 build-cov && \
    cp -a jq-1.8.1 build-uftrace && \
    rm -rf jq-1.8.1

# ==================== Build fuzz binary ====================
WORKDIR /work/build-fuzz
RUN autoreconf -fi

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --with-oniguruma=builtin --disable-shared --enable-all-static && \
    make -j$(nproc)

RUN afl-clang-lto -O2 -c tests/jq_fuzz_compile.c \
    -I./src -o ./jq_fuzz_compile.o && \
    afl-clang-lto++ -O2 \
    -fsanitize=fuzzer \
    -static -Wl,--allow-multiple-definition \
    ./jq_fuzz_compile.o \
    ./.libs/libjq.a ./vendor/oniguruma/src/.libs/libonig.a \
    -o jq_fuzz_compile

WORKDIR /work
RUN ln -s build-fuzz/jq_fuzz_compile bin-fuzz

# ==================== Build cmplog binary ====================
WORKDIR /work/build-cmplog
RUN autoreconf -fi

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --with-oniguruma=builtin --disable-shared --enable-all-static && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -c tests/jq_fuzz_compile.c \
    -I./src -o ./jq_fuzz_compile.o && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto++ -O2 \
    -fsanitize=fuzzer \
    -static -Wl,--allow-multiple-definition \
    ./jq_fuzz_compile.o \
    ./.libs/libjq.a ./vendor/oniguruma/src/.libs/libonig.a \
    -o jq_fuzz_compile

WORKDIR /work
RUN ln -s build-cmplog/jq_fuzz_compile bin-cmplog

# ==================== Copy fuzzing resources ====================
COPY jq-harness/fuzz/dict /work/dict
COPY jq-harness/fuzz/in /work/in
COPY jq-harness/fuzz/fuzz.sh /work/fuzz.sh
COPY jq-harness/fuzz/whatsup.sh /work/whatsup.sh
COPY jq-harness/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY jq-harness/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY jq-harness/fuzz/collect-branch.py /work/collect-branch.py
COPY jq-harness/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# ==================== Build cov binary ====================
WORKDIR /work/build-cov
RUN autoreconf -fi

RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    CXXFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --with-oniguruma=builtin --disable-shared --enable-all-static && \
    make -j$(nproc)

RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -c tests/jq_fuzz_compile.c \
    -I./src -o ./jq_fuzz_compile.o

# For coverage binary, we need a main function (not fuzzer main)
RUN printf '%s\n' \
    '#include <stdio.h>' \
    '#include <stdlib.h>' \
    '#include <stdint.h>' \
    '' \
    'extern int LLVMFuzzerTestOneInput(uint8_t *data, size_t size);' \
    '' \
    'int main(int argc, char **argv) {' \
    '    if (argc < 2) {' \
    '        fprintf(stderr, "Usage: %%s <input_file>\\n", argv[0]);' \
    '        return 1;' \
    '    }' \
    '    FILE *f = fopen(argv[1], "rb");' \
    '    if (!f) {' \
    '        perror("fopen");' \
    '        return 1;' \
    '    }' \
    '    fseek(f, 0, SEEK_END);' \
    '    long size = ftell(f);' \
    '    fseek(f, 0, SEEK_SET);' \
    '    uint8_t *data = (uint8_t*)malloc(size);' \
    '    if (fread(data, 1, size, f) != (size_t)size) {' \
    '        perror("fread");' \
    '        return 1;' \
    '    }' \
    '    fclose(f);' \
    '    LLVMFuzzerTestOneInput(data, size);' \
    '    free(data);' \
    '    return 0;' \
    '}' > fuzz_main.c && \
    clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -c fuzz_main.c -o fuzz_main.o && \
    clang++ -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -static -Wl,--allow-multiple-definition \
    ./fuzz_main.o ./jq_fuzz_compile.o \
    ./.libs/libjq.a ./vendor/oniguruma/src/.libs/libonig.a \
    -o jq_fuzz_compile

WORKDIR /work
RUN ln -s build-cov/jq_fuzz_compile bin-cov && \
    rm -f *.profraw

# ==================== Build uftrace binary ====================
WORKDIR /work/build-uftrace
RUN autoreconf -fi

RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    CXXFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --with-oniguruma=builtin --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

RUN clang -g -O0 -pg -fno-omit-frame-pointer -c tests/jq_fuzz_compile.c \
    -I/work/install-uftrace/include -o ./jq_fuzz_compile.o

RUN printf '%s\n' \
    '#include <stdio.h>' \
    '#include <stdlib.h>' \
    '#include <stdint.h>' \
    '' \
    'extern int LLVMFuzzerTestOneInput(uint8_t *data, size_t size);' \
    '' \
    'int main(int argc, char **argv) {' \
    '    if (argc < 2) {' \
    '        fprintf(stderr, "Usage: %%s <input_file>\\n", argv[0]);' \
    '        return 1;' \
    '    }' \
    '    FILE *f = fopen(argv[1], "rb");' \
    '    if (!f) {' \
    '        perror("fopen");' \
    '        return 1;' \
    '    }' \
    '    fseek(f, 0, SEEK_END);' \
    '    long size = ftell(f);' \
    '    fseek(f, 0, SEEK_SET);' \
    '    uint8_t *data = (uint8_t*)malloc(size);' \
    '    if (fread(data, 1, size, f) != (size_t)size) {' \
    '        perror("fread");' \
    '        return 1;' \
    '    }' \
    '    fclose(f);' \
    '    LLVMFuzzerTestOneInput(data, size);' \
    '    free(data);' \
    '    return 0;' \
    '}' > fuzz_main.c && \
    clang -g -O0 -pg -fno-omit-frame-pointer -c fuzz_main.c -o fuzz_main.o && \
    clang++ -g -O0 -pg -fno-omit-frame-pointer \
    -Wl,--allow-multiple-definition \
    ./fuzz_main.o ./jq_fuzz_compile.o \
    /work/install-uftrace/lib/libjq.a /work/build-uftrace/vendor/oniguruma/src/.libs/libonig.a \
    -o jq_fuzz_compile

WORKDIR /work
RUN ln -s build-uftrace/jq_fuzz_compile bin-uftrace && \
    rm -rf uftrace.data gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
