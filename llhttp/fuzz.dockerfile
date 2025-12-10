FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract llhttp v9.2.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.2.1.tar.gz && \
    tar -xzf v9.2.1.tar.gz && \
    rm v9.2.1.tar.gz

WORKDIR /src/llhttp-release-v9.2.1

# Build llhttp with afl-clang-lto for fuzzing
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_STATIC_LIBS=ON

RUN cd build && make -j$(nproc)

# Create harness
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

RUN afl-clang-lto -O2 -I./include -L./build -o /out/llhttp_harness harness.c build/libllhttp.a -static -Wl,--allow-multiple-definition

# Build CMPLOG version
WORKDIR /src
RUN rm -rf llhttp-release-v9.2.1 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.2.1.tar.gz && \
    tar -xzf v9.2.1.tar.gz && \
    rm v9.2.1.tar.gz

WORKDIR /src/llhttp-release-v9.2.1

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_STATIC_LIBS=ON

RUN AFL_LLVM_CMPLOG=1 cd build && make -j$(nproc)

# Create harness again for CMPLOG
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

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I./include -L./build -o /out/llhttp_harness.cmplog harness.c build/libllhttp.a -static -Wl,--allow-multiple-definition

# Copy fuzzing resources
COPY llhttp/fuzz/dict /out/dict
COPY llhttp/fuzz/in /out/in
COPY llhttp/fuzz/fuzz.sh /out/fuzz.sh
COPY llhttp/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/llhttp_harness /out/llhttp_harness.cmplog && \
    file /out/llhttp_harness

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing llhttp'"]
