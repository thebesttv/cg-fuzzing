FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libssl-dev zlib1g-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: civetweb" > /work/proj && \
    echo "version: 1.16" >> /work/proj && \
    echo "source: https://github.com/civetweb/civetweb/archive/refs/tags/v1.16.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/civetweb/civetweb/archive/refs/tags/v1.16.tar.gz && \
    tar -xzf v1.16.tar.gz && \
    rm v1.16.tar.gz && \
    cp -a civetweb-1.16 build-fuzz && \
    cp -a civetweb-1.16 build-cmplog && \
    cp -a civetweb-1.16 build-cov && \
    cp -a civetweb-1.16 build-uftrace && \
    rm -rf civetweb-1.16

# Copy harness for all builds
COPY civetweb/fuzz/harness/afl_http.c /work/afl_http.c

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2 -DNO_SSL" \
    make lib

RUN afl-clang-lto -O2 -I/work/build-fuzz/include -I/work/build-fuzz/src \
    -D_GNU_SOURCE -DNO_SSL -DUSE_IPV6 -DUSE_WEBSOCKET -DMG_EXPERIMENTAL_INTERFACES \
    /work/afl_http.c \
    -o civetweb_url_fuzz \
    -lpthread -ldl

WORKDIR /work
RUN ln -s build-fuzz/civetweb_url_fuzz bin-fuzz && \
    echo "Fuzz binary built successfully"

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2 -DNO_SSL" \
    AFL_LLVM_CMPLOG=1 \
    make lib

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I/work/build-cmplog/include -I/work/build-cmplog/src \
    -D_GNU_SOURCE -DNO_SSL -DUSE_IPV6 -DUSE_WEBSOCKET -DMG_EXPERIMENTAL_INTERFACES \
    /work/afl_http.c \
    -o civetweb_url_fuzz \
    -lpthread -ldl

WORKDIR /work
RUN ln -s build-cmplog/civetweb_url_fuzz bin-cmplog && \
    echo "Cmplog binary built successfully"

# Copy fuzzing resources
COPY civetweb/fuzz/dict /work/dict
COPY civetweb/fuzz/in /work/in
COPY civetweb/fuzz/fuzz.sh /work/fuzz.sh
COPY civetweb/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping -DNO_SSL" \
    make lib

# For cov/uftrace, we need to link against libcivetweb.a instead of including civetweb.c directly
# Create a modified harness that doesn't include civetweb.c
RUN printf '%s\n' \
    '/* AFL harness for civetweb URL parsing - linked version */' \
    '#include <stdio.h>' \
    '#include <stdlib.h>' \
    '#include <string.h>' \
    '#include <stdint.h>' \
    '' \
    '/* Include only the header */' \
    '#include "civetweb.h"' \
    '' \
    'int main(int argc, char **argv) {' \
    '    if (argc < 2) {' \
    '        fprintf(stderr, "Usage: %s <input_file>\\n", argv[0]);' \
    '        return 1;' \
    '    }' \
    '    FILE *f = fopen(argv[1], "rb");' \
    '    if (!f) return 1;' \
    '    fseek(f, 0, SEEK_END);' \
    '    long size = ftell(f);' \
    '    fseek(f, 0, SEEK_SET);' \
    '    unsigned char *data = malloc(size + 1);' \
    '    if (!data) { fclose(f); return 1; }' \
    '    fread(data, 1, size, f);' \
    '    data[size] = 0;' \
    '    fclose(f);' \
    '    ' \
    '    if (size >= 1 && size <= 65536) {' \
    '        /* Test URL decode */' \
    '        char decoded[65536];' \
    '        int decoded_len = mg_url_decode((const char *)data, size, decoded, sizeof(decoded), 0);' \
    '        (void)decoded_len;' \
    '' \
    '        /* Test variable extraction */' \
    '        char var_buf[1024];' \
    '        int var_len = mg_get_var2((const char *)data, size, "test", var_buf, sizeof(var_buf), 0);' \
    '        (void)var_len;' \
    '' \
    '        /* Test cookie extraction */' \
    '        var_len = mg_get_cookie((const char *)data, "session", var_buf, sizeof(var_buf));' \
    '        (void)var_len;' \
    '    }' \
    '' \
    '    free(data);' \
    '    return 0;' \
    '}' \
    > /work/afl_http_linked.c

RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -I/work/build-cov/include \
    -D_GNU_SOURCE -DNO_SSL \
    /work/afl_http_linked.c \
    -o civetweb_url_fuzz \
    /work/build-cov/libcivetweb.a \
    -lpthread -ldl

WORKDIR /work
RUN ln -s build-cov/civetweb_url_fuzz bin-cov && \
    echo "Cov binary built successfully" && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer -DNO_SSL" \
    make lib

RUN clang -g -O0 -pg -fno-omit-frame-pointer \
    -I/work/build-uftrace/include \
    -D_GNU_SOURCE -DNO_SSL \
    /work/afl_http_linked.c \
    -o civetweb_url_fuzz \
    /work/build-uftrace/libcivetweb.a \
    -lpthread -ldl

WORKDIR /work
RUN ln -s build-uftrace/civetweb_url_fuzz bin-uftrace && \
    echo "Uftrace binary built successfully" && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
