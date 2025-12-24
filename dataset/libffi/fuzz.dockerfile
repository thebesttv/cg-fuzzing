FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool texinfo uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: libffi" > /work/proj && \
    echo "version: 3.4.6" >> /work/proj && \
    echo "source: https://github.com/libffi/libffi/releases/download/v3.4.6/libffi-3.4.6.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/libffi/libffi/releases/download/v3.4.6/libffi-3.4.6.tar.gz && \
    tar -xzf libffi-3.4.6.tar.gz && \
    rm libffi-3.4.6.tar.gz && \
    cp -a libffi-3.4.6 build-fuzz && \
    cp -a libffi-3.4.6 build-cmplog && \
    cp -a libffi-3.4.6 build-cov && \
    cp -a libffi-3.4.6 build-uftrace && \
    rm -rf libffi-3.4.6

# Create fuzzing harness for AFL builds
RUN printf '%s\n' \
    '#include <stdio.h>' \
    '#include <stdlib.h>' \
    '#include <string.h>' \
    '#include <stdint.h>' \
    '#include <unistd.h>' \
    '#include <ffi.h>' \
    '' \
    '__AFL_FUZZ_INIT();' \
    '' \
    'void test_func(int a, int b, int c) { }' \
    '' \
    'int main() {' \
    '    __AFL_INIT();' \
    '    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;' \
    '    while (__AFL_LOOP(10000)) {' \
    '        int len = __AFL_FUZZ_TESTCASE_LEN;' \
    '        if (len < 12) continue;' \
    '        int nargs = buf[0] % 10;' \
    '        if (nargs < 1) nargs = 3;' \
    '        ffi_cif cif;' \
    '        ffi_type **args = malloc(sizeof(ffi_type*) * nargs);' \
    '        void **values = malloc(sizeof(void*) * nargs);' \
    '        int *arg_vals = malloc(sizeof(int) * nargs);' \
    '        for (int i = 0; i < nargs && i < len - 1; i++) {' \
    '            args[i] = &ffi_type_sint;' \
    '            arg_vals[i] = (int)buf[i + 1];' \
    '            values[i] = &arg_vals[i];' \
    '        }' \
    '        if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, nargs, &ffi_type_void, args) == FFI_OK) {' \
    '            ffi_call(&cif, (void(*)(void))test_func, NULL, values);' \
    '        }' \
    '        free(args);' \
    '        free(values);' \
    '        free(arg_vals);' \
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
    '#include <ffi.h>' \
    '' \
    'void test_func(int a, int b, int c) { }' \
    '' \
    'int main() {' \
    '    unsigned char buf[1024];' \
    '    ssize_t len = read(0, buf, sizeof(buf));' \
    '    if (len < 12) return 0;' \
    '    int nargs = buf[0] % 10;' \
    '    if (nargs < 1) nargs = 3;' \
    '    ffi_cif cif;' \
    '    ffi_type **args = malloc(sizeof(ffi_type*) * nargs);' \
    '    void **values = malloc(sizeof(void*) * nargs);' \
    '    int *arg_vals = malloc(sizeof(int) * nargs);' \
    '    for (int i = 0; i < nargs && i < len - 1; i++) {' \
    '        args[i] = &ffi_type_sint;' \
    '        arg_vals[i] = (int)buf[i + 1];' \
    '        values[i] = &arg_vals[i];' \
    '    }' \
    '    if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, nargs, &ffi_type_void, args) == FFI_OK) {' \
    '        ffi_call(&cif, (void(*)(void))test_func, NULL, values);' \
    '    }' \
    '    free(args);' \
    '    free(values);' \
    '    free(arg_vals);' \
    '    return 0;' \
    '}' \
    > /work/simple_harness.c

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN afl-clang-lto -O2 \
    -I build-fuzz/include -I build-fuzz/x86_64-pc-linux-gnu/include \
    fuzz_harness.c \
    build-fuzz/x86_64-pc-linux-gnu/.libs/libffi.a \
    -static -Wl,--allow-multiple-definition \
    -o bin-fuzz && \
    echo "test" | /work/bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 \
    -I build-cmplog/include -I build-cmplog/x86_64-pc-linux-gnu/include \
    fuzz_harness.c \
    build-cmplog/x86_64-pc-linux-gnu/.libs/libffi.a \
    -static -Wl,--allow-multiple-definition \
    -o bin-cmplog && \
    echo "test" | /work/bin-cmplog

# Copy fuzzing resources
COPY libffi/fuzz/dict /work/dict
COPY libffi/fuzz/in /work/in
COPY libffi/fuzz/fuzz.sh /work/fuzz.sh
COPY libffi/fuzz/whatsup.sh /work/whatsup.sh
COPY libffi/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY libffi/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY libffi/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -I build-cov/include -I build-cov/x86_64-pc-linux-gnu/include \
    simple_harness.c \
    build-cov/x86_64-pc-linux-gnu/.libs/libffi.a \
    -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition \
    -o bin-cov && \
    echo "test" | /work/bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN clang -g -O0 -pg -fno-omit-frame-pointer \
    -I build-uftrace/include -I build-uftrace/x86_64-pc-linux-gnu/include \
    simple_harness.c \
    build-uftrace/x86_64-pc-linux-gnu/.libs/libffi.a \
    -pg -Wl,--allow-multiple-definition \
    -o bin-uftrace && \
    echo "test" | /work/bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
