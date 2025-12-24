FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget unzip uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: nanosvg" > /work/proj && \
    echo "version: master" >> /work/proj && \
    echo "source: https://github.com/memononen/nanosvg" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/memononen/nanosvg/archive/refs/heads/master.zip && \
    unzip master.zip && \
    rm master.zip && \
    cp -a nanosvg-master build-fuzz && \
    cp -a nanosvg-master build-cmplog && \
    cp -a nanosvg-master build-cov && \
    cp -a nanosvg-master build-uftrace && \
    rm -rf nanosvg-master

# Create fuzzing harness for AFL builds
RUN printf '%s\n' \
    '#define NANOSVG_IMPLEMENTATION' \
    '#include "src/nanosvg.h"' \
    '#include <stdio.h>' \
    '#include <stdlib.h>' \
    '#include <string.h>' \
    '#include <stdint.h>' \
    '#include <unistd.h>' \
    '' \
    '__AFL_FUZZ_INIT();' \
    '' \
    'int main() {' \
    '    __AFL_INIT();' \
    '    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;' \
    '    while (__AFL_LOOP(10000)) {' \
    '        size_t len = __AFL_FUZZ_TESTCASE_LEN;' \
    '        if (len < 1 || len > 64*1024) continue;' \
    '        char *svg_data = (char*)malloc(len + 1);' \
    '        memcpy(svg_data, buf, len);' \
    '        svg_data[len] = 0;' \
    '        NSVGimage *image = nsvgParse(svg_data, "px", 96.0f);' \
    '        if (image) nsvgDelete(image);' \
    '        free(svg_data);' \
    '    }' \
    '    return 0;' \
    '}' \
    > /work/fuzz_harness.c

# Create simple harness for coverage/uftrace builds (no AFL macros)
RUN printf '%s\n' \
    '#define NANOSVG_IMPLEMENTATION' \
    '#include "src/nanosvg.h"' \
    '#include <stdio.h>' \
    '#include <stdlib.h>' \
    '#include <string.h>' \
    '#include <stdint.h>' \
    '#include <unistd.h>' \
    '' \
    'int main() {' \
    '    unsigned char buf[64*1024];' \
    '    ssize_t len = read(0, buf, sizeof(buf) - 1);' \
    '    if (len < 1) return 0;' \
    '    buf[len] = 0;' \
    '    NSVGimage *image = nsvgParse((char*)buf, "px", 96.0f);' \
    '    if (image) nsvgDelete(image);' \
    '    return 0;' \
    '}' \
    > /work/simple_harness.c

# Build fuzz binary with afl-clang-lto
WORKDIR /work
RUN afl-clang-lto -O2 \
    -I build-fuzz \
    fuzz_harness.c \
    -static -Wl,--allow-multiple-definition \
    -lm \
    -o bin-fuzz && \
    echo "<svg></svg>" | /work/bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 \
    -I build-cmplog \
    fuzz_harness.c \
    -static -Wl,--allow-multiple-definition \
    -lm \
    -o bin-cmplog && \
    echo "<svg></svg>" | /work/bin-cmplog

# Copy fuzzing resources
COPY nanosvg/fuzz/dict /work/dict
COPY nanosvg/fuzz/in /work/in
COPY nanosvg/fuzz/fuzz.sh /work/fuzz.sh
COPY nanosvg/fuzz/whatsup.sh /work/whatsup.sh
COPY nanosvg/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY nanosvg/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY nanosvg/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work
RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -I build-cov \
    simple_harness.c \
    -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition \
    -lm \
    -o bin-cov && \
    echo "<svg></svg>" | /work/bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work
RUN clang -g -O0 -pg -fno-omit-frame-pointer \
    -I build-uftrace \
    simple_harness.c \
    -pg -Wl,--allow-multiple-definition \
    -lm \
    -o bin-uftrace && \
    echo "<svg></svg>" | /work/bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
