FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget meson ninja-build pkg-config xz-utils uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: harfbuzz" > /work/proj && \
    echo "version: 10.1.0" >> /work/proj && \
    echo "source: https://github.com/harfbuzz/harfbuzz/releases/download/10.1.0/harfbuzz-10.1.0.tar.xz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/harfbuzz/harfbuzz/releases/download/10.1.0/harfbuzz-10.1.0.tar.xz && \
    tar -xf harfbuzz-10.1.0.tar.xz && \
    rm harfbuzz-10.1.0.tar.xz && \
    cp -a harfbuzz-10.1.0 build-fuzz && \
    cp -a harfbuzz-10.1.0 build-cmplog && \
    cp -a harfbuzz-10.1.0 build-cov && \
    cp -a harfbuzz-10.1.0 build-uftrace && \
    rm -rf harfbuzz-10.1.0

# Create fuzzing harness for AFL builds
RUN printf '%s\n' \
    '#include <stdio.h>' \
    '#include <stdlib.h>' \
    '#include <string.h>' \
    '#include <stdint.h>' \
    '#include <unistd.h>' \
    '#include <hb.h>' \
    '' \
    '__AFL_FUZZ_INIT();' \
    '' \
    'int main() {' \
    '    __AFL_INIT();' \
    '    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;' \
    '    while (__AFL_LOOP(10000)) {' \
    '        int len = __AFL_FUZZ_TESTCASE_LEN;' \
    '        if (len < 10) continue;' \
    '        hb_blob_t *blob = hb_blob_create((const char *)buf, len, HB_MEMORY_MODE_READONLY, NULL, NULL);' \
    '        hb_face_t *face = hb_face_create(blob, 0);' \
    '        hb_font_t *font = hb_font_create(face);' \
    '        hb_buffer_t *buffer = hb_buffer_create();' \
    '        const char *text = "Hello World";' \
    '        hb_buffer_add_utf8(buffer, text, -1, 0, -1);' \
    '        hb_buffer_guess_segment_properties(buffer);' \
    '        hb_shape(font, buffer, NULL, 0);' \
    '        hb_buffer_destroy(buffer);' \
    '        hb_font_destroy(font);' \
    '        hb_face_destroy(face);' \
    '        hb_blob_destroy(blob);' \
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
    '#include <hb.h>' \
    '' \
    'int main() {' \
    '    unsigned char buf[1024*1024];' \
    '    ssize_t len = read(0, buf, sizeof(buf));' \
    '    if (len < 10) return 0;' \
    '    hb_blob_t *blob = hb_blob_create((const char *)buf, len, HB_MEMORY_MODE_READONLY, NULL, NULL);' \
    '    hb_face_t *face = hb_face_create(blob, 0);' \
    '    hb_font_t *font = hb_font_create(face);' \
    '    hb_buffer_t *buffer = hb_buffer_create();' \
    '    const char *text = "Hello World";' \
    '    hb_buffer_add_utf8(buffer, text, -1, 0, -1);' \
    '    hb_buffer_guess_segment_properties(buffer);' \
    '    hb_shape(font, buffer, NULL, 0);' \
    '    hb_buffer_destroy(buffer);' \
    '    hb_font_destroy(font);' \
    '    hb_face_destroy(face);' \
    '    hb_blob_destroy(blob);' \
    '    return 0;' \
    '}' \
    > /work/simple_harness.c

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    meson setup .. \
        --default-library=static \
        -Dtests=disabled \
        -Dutilities=disabled \
        -Ddocs=disabled \
        -Dfreetype=disabled \
        -Dglib=disabled && \
    ninja

WORKDIR /work
RUN afl-clang-lto -O2 \
    -I build-fuzz/src \
    fuzz_harness.c \
    build-fuzz/build/src/libharfbuzz.a \
    -static -Wl,--allow-multiple-definition \
    -lm \
    -o bin-fuzz && \
    echo "test" | /work/bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    meson setup .. \
        --default-library=static \
        -Dtests=disabled \
        -Dutilities=disabled \
        -Ddocs=disabled \
        -Dfreetype=disabled \
        -Dglib=disabled && \
    AFL_LLVM_CMPLOG=1 ninja

WORKDIR /work
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 \
    -I build-cmplog/src \
    fuzz_harness.c \
    build-cmplog/build/src/libharfbuzz.a \
    -static -Wl,--allow-multiple-definition \
    -lm \
    -o bin-cmplog && \
    echo "test" | /work/bin-cmplog

# Copy fuzzing resources
COPY harfbuzz/fuzz/dict /work/dict
COPY harfbuzz/fuzz/in /work/in
COPY harfbuzz/fuzz/fuzz.sh /work/fuzz.sh
COPY harfbuzz/fuzz/whatsup.sh /work/whatsup.sh
COPY harfbuzz/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY harfbuzz/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY harfbuzz/fuzz/collect-branch.py /work/collect-branch.py
COPY harfbuzz/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    CXXFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    meson setup .. \
        --default-library=static \
        -Dtests=disabled \
        -Dutilities=disabled \
        -Ddocs=disabled \
        -Dfreetype=disabled \
        -Dglib=disabled && \
    ninja

WORKDIR /work
RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -I build-cov/src \
    simple_harness.c \
    build-cov/build/src/libharfbuzz.a \
    -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition \
    -lm \
    -o bin-cov && \
    echo "test" | /work/bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    CXXFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    meson setup .. \
        --default-library=static \
        -Dtests=disabled \
        -Dutilities=disabled \
        -Ddocs=disabled \
        -Dfreetype=disabled \
        -Dglib=disabled && \
    ninja

WORKDIR /work
RUN clang -g -O0 -pg -fno-omit-frame-pointer \
    -I build-uftrace/src \
    simple_harness.c \
    build-uftrace/build/src/libharfbuzz.a \
    -pg -Wl,--allow-multiple-definition \
    -lm \
    -o bin-uftrace && \
    echo "test" | /work/bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
