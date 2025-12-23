FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract llhttp v9.2.1

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: llhttp" > /work/proj && \
    echo "version: 9.2.1" >> /work/proj && \
    echo "source: https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.2.1.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.2.1.tar.gz && \
    tar -xzf v9.2.1.tar.gz && \
    mv v9.2.1 build && \
    rm v9.2.1.tar.gz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build llhttp with CMake and WLLVM
RUN mkdir build && cd build && \
    CC=wllvm \
    cmake .. \
    -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_STATIC_LIBS=ON

RUN cd build && make -j$(nproc)

# llhttp is a library. Create a simple harness to extract bitcode.
RUN printf '%s\n' '#include "llhttp.h"' \
    '#include <stdio.h>' \
    '#include <stdlib.h>' \
    '#include <string.h>' \
    '' \
    'int on_message_complete(llhttp_t* parser) {' \
    '    return 0;' \
    '}' \
    '' \
    'int main(int argc, char **argv) {' \
    '    if (argc < 2) {' \
    '        fprintf(stderr, "Usage: %s <http_request_file>\\n", argv[0]);' \
    '        return 1;' \
    '    }' \
    '    ' \
    '    FILE *f = fopen(argv[1], "rb");' \
    '    if (!f) {' \
    '        perror("fopen");' \
    '        return 1;' \
    '    }' \
    '    ' \
    '    fseek(f, 0, SEEK_END);' \
    '    long len = ftell(f);' \
    '    fseek(f, 0, SEEK_SET);' \
    '    ' \
    '    char *buf = malloc(len + 1);' \
    '    fread(buf, 1, len, f);' \
    '    buf[len] = 0;' \
    '    fclose(f);' \
    '    ' \
    '    llhttp_t parser;' \
    '    llhttp_settings_t settings;' \
    '    ' \
    '    llhttp_settings_init(&settings);' \
    '    settings.on_message_complete = on_message_complete;' \
    '    ' \
    '    llhttp_init(&parser, HTTP_BOTH, &settings);' \
    '    ' \
    '    enum llhttp_errno err = llhttp_execute(&parser, buf, len);' \
    '    ' \
    '    if (err != HPE_OK) {' \
    '        fprintf(stderr, "Parse error: %s %s\\n", llhttp_errno_name(err), llhttp_get_error_reason(&parser));' \
    '    }' \
    '    ' \
    '    free(buf);' \
    '    return 0;' \
    '}' > harness.c

RUN wllvm -g -O0 -Xclang -disable-llvm-passes -I./include -L./build -o llhttp_harness harness.c build/libllhttp.a -static -Wl,--allow-multiple-definition

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc llhttp_harness && \
    mv llhttp_harness.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
