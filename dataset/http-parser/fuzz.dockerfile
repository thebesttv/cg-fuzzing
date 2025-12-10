FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract http-parser v2.9.4
WORKDIR /src
RUN wget https://github.com/nodejs/http-parser/archive/refs/tags/v2.9.4.tar.gz && \
    tar -xzf v2.9.4.tar.gz && \
    rm v2.9.4.tar.gz

WORKDIR /src/http-parser-2.9.4

# Create fuzzing harness
RUN echo '#include <stdio.h>' > fuzz_harness.c && \
    echo '#include <stdlib.h>' >> fuzz_harness.c && \
    echo '#include <string.h>' >> fuzz_harness.c && \
    echo '#include "http_parser.h"' >> fuzz_harness.c && \
    echo '#define MAX_INPUT_SIZE (1024 * 1024)' >> fuzz_harness.c && \
    echo 'static int on_message_begin(http_parser* p) { return 0; }' >> fuzz_harness.c && \
    echo 'static int on_url(http_parser* p, const char* at, size_t len) { return 0; }' >> fuzz_harness.c && \
    echo 'static int on_status(http_parser* p, const char* at, size_t len) { return 0; }' >> fuzz_harness.c && \
    echo 'static int on_header_field(http_parser* p, const char* at, size_t len) { return 0; }' >> fuzz_harness.c && \
    echo 'static int on_header_value(http_parser* p, const char* at, size_t len) { return 0; }' >> fuzz_harness.c && \
    echo 'static int on_headers_complete(http_parser* p) { return 0; }' >> fuzz_harness.c && \
    echo 'static int on_body(http_parser* p, const char* at, size_t len) { return 0; }' >> fuzz_harness.c && \
    echo 'static int on_message_complete(http_parser* p) { return 0; }' >> fuzz_harness.c && \
    echo 'static int on_chunk_header(http_parser* p) { return 0; }' >> fuzz_harness.c && \
    echo 'static int on_chunk_complete(http_parser* p) { return 0; }' >> fuzz_harness.c && \
    echo 'int main(int argc, char *argv[]) {' >> fuzz_harness.c && \
    echo '    FILE *f;' >> fuzz_harness.c && \
    echo '    char *input = NULL;' >> fuzz_harness.c && \
    echo '    size_t input_size;' >> fuzz_harness.c && \
    echo '    http_parser parser;' >> fuzz_harness.c && \
    echo '    http_parser_settings settings;' >> fuzz_harness.c && \
    echo '    if (argc < 2) { fprintf(stderr, "Usage: %s <input_file>\\n", argv[0]); return 1; }' >> fuzz_harness.c && \
    echo '    f = fopen(argv[1], "rb");' >> fuzz_harness.c && \
    echo '    if (!f) { fprintf(stderr, "Cannot open file: %s\\n", argv[1]); return 1; }' >> fuzz_harness.c && \
    echo '    fseek(f, 0, SEEK_END);' >> fuzz_harness.c && \
    echo '    input_size = ftell(f);' >> fuzz_harness.c && \
    echo '    rewind(f);' >> fuzz_harness.c && \
    echo '    if (input_size == 0 || input_size > MAX_INPUT_SIZE) { fclose(f); return 0; }' >> fuzz_harness.c && \
    echo '    input = (char *)malloc(input_size);' >> fuzz_harness.c && \
    echo '    if (!input) { fclose(f); return 1; }' >> fuzz_harness.c && \
    echo '    if (fread(input, 1, input_size, f) != input_size) { free(input); fclose(f); return 1; }' >> fuzz_harness.c && \
    echo '    fclose(f);' >> fuzz_harness.c && \
    echo '    http_parser_settings_init(&settings);' >> fuzz_harness.c && \
    echo '    settings.on_message_begin = on_message_begin;' >> fuzz_harness.c && \
    echo '    settings.on_url = on_url;' >> fuzz_harness.c && \
    echo '    settings.on_status = on_status;' >> fuzz_harness.c && \
    echo '    settings.on_header_field = on_header_field;' >> fuzz_harness.c && \
    echo '    settings.on_header_value = on_header_value;' >> fuzz_harness.c && \
    echo '    settings.on_headers_complete = on_headers_complete;' >> fuzz_harness.c && \
    echo '    settings.on_body = on_body;' >> fuzz_harness.c && \
    echo '    settings.on_message_complete = on_message_complete;' >> fuzz_harness.c && \
    echo '    settings.on_chunk_header = on_chunk_header;' >> fuzz_harness.c && \
    echo '    settings.on_chunk_complete = on_chunk_complete;' >> fuzz_harness.c && \
    echo '    http_parser_init(&parser, HTTP_REQUEST);' >> fuzz_harness.c && \
    echo '    http_parser_execute(&parser, &settings, input, input_size);' >> fuzz_harness.c && \
    echo '    http_parser_init(&parser, HTTP_RESPONSE);' >> fuzz_harness.c && \
    echo '    http_parser_execute(&parser, &settings, input, input_size);' >> fuzz_harness.c && \
    echo '    http_parser_init(&parser, HTTP_BOTH);' >> fuzz_harness.c && \
    echo '    http_parser_execute(&parser, &settings, input, input_size);' >> fuzz_harness.c && \
    echo '    free(input);' >> fuzz_harness.c && \
    echo '    return 0;' >> fuzz_harness.c && \
    echo '}' >> fuzz_harness.c

# Build http-parser with afl-clang-lto
RUN afl-clang-lto \
    -O2 \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o http_parser_fuzz \
    fuzz_harness.c http_parser.c

RUN cp http_parser_fuzz /out/http_parser_fuzz

# Build CMPLOG version
WORKDIR /src
RUN rm -rf http-parser-2.9.4 && \
    wget https://github.com/nodejs/http-parser/archive/refs/tags/v2.9.4.tar.gz && \
    tar -xzf v2.9.4.tar.gz && \
    rm v2.9.4.tar.gz

WORKDIR /src/http-parser-2.9.4

RUN echo '#include <stdio.h>' > fuzz_harness.c && \
    echo '#include <stdlib.h>' >> fuzz_harness.c && \
    echo '#include <string.h>' >> fuzz_harness.c && \
    echo '#include "http_parser.h"' >> fuzz_harness.c && \
    echo '#define MAX_INPUT_SIZE (1024 * 1024)' >> fuzz_harness.c && \
    echo 'static int on_message_begin(http_parser* p) { return 0; }' >> fuzz_harness.c && \
    echo 'static int on_url(http_parser* p, const char* at, size_t len) { return 0; }' >> fuzz_harness.c && \
    echo 'static int on_status(http_parser* p, const char* at, size_t len) { return 0; }' >> fuzz_harness.c && \
    echo 'static int on_header_field(http_parser* p, const char* at, size_t len) { return 0; }' >> fuzz_harness.c && \
    echo 'static int on_header_value(http_parser* p, const char* at, size_t len) { return 0; }' >> fuzz_harness.c && \
    echo 'static int on_headers_complete(http_parser* p) { return 0; }' >> fuzz_harness.c && \
    echo 'static int on_body(http_parser* p, const char* at, size_t len) { return 0; }' >> fuzz_harness.c && \
    echo 'static int on_message_complete(http_parser* p) { return 0; }' >> fuzz_harness.c && \
    echo 'static int on_chunk_header(http_parser* p) { return 0; }' >> fuzz_harness.c && \
    echo 'static int on_chunk_complete(http_parser* p) { return 0; }' >> fuzz_harness.c && \
    echo 'int main(int argc, char *argv[]) {' >> fuzz_harness.c && \
    echo '    FILE *f;' >> fuzz_harness.c && \
    echo '    char *input = NULL;' >> fuzz_harness.c && \
    echo '    size_t input_size;' >> fuzz_harness.c && \
    echo '    http_parser parser;' >> fuzz_harness.c && \
    echo '    http_parser_settings settings;' >> fuzz_harness.c && \
    echo '    if (argc < 2) { fprintf(stderr, "Usage: %s <input_file>\\n", argv[0]); return 1; }' >> fuzz_harness.c && \
    echo '    f = fopen(argv[1], "rb");' >> fuzz_harness.c && \
    echo '    if (!f) { fprintf(stderr, "Cannot open file: %s\\n", argv[1]); return 1; }' >> fuzz_harness.c && \
    echo '    fseek(f, 0, SEEK_END);' >> fuzz_harness.c && \
    echo '    input_size = ftell(f);' >> fuzz_harness.c && \
    echo '    rewind(f);' >> fuzz_harness.c && \
    echo '    if (input_size == 0 || input_size > MAX_INPUT_SIZE) { fclose(f); return 0; }' >> fuzz_harness.c && \
    echo '    input = (char *)malloc(input_size);' >> fuzz_harness.c && \
    echo '    if (!input) { fclose(f); return 1; }' >> fuzz_harness.c && \
    echo '    if (fread(input, 1, input_size, f) != input_size) { free(input); fclose(f); return 1; }' >> fuzz_harness.c && \
    echo '    fclose(f);' >> fuzz_harness.c && \
    echo '    http_parser_settings_init(&settings);' >> fuzz_harness.c && \
    echo '    settings.on_message_begin = on_message_begin;' >> fuzz_harness.c && \
    echo '    settings.on_url = on_url;' >> fuzz_harness.c && \
    echo '    settings.on_status = on_status;' >> fuzz_harness.c && \
    echo '    settings.on_header_field = on_header_field;' >> fuzz_harness.c && \
    echo '    settings.on_header_value = on_header_value;' >> fuzz_harness.c && \
    echo '    settings.on_headers_complete = on_headers_complete;' >> fuzz_harness.c && \
    echo '    settings.on_body = on_body;' >> fuzz_harness.c && \
    echo '    settings.on_message_complete = on_message_complete;' >> fuzz_harness.c && \
    echo '    settings.on_chunk_header = on_chunk_header;' >> fuzz_harness.c && \
    echo '    settings.on_chunk_complete = on_chunk_complete;' >> fuzz_harness.c && \
    echo '    http_parser_init(&parser, HTTP_REQUEST);' >> fuzz_harness.c && \
    echo '    http_parser_execute(&parser, &settings, input, input_size);' >> fuzz_harness.c && \
    echo '    http_parser_init(&parser, HTTP_RESPONSE);' >> fuzz_harness.c && \
    echo '    http_parser_execute(&parser, &settings, input, input_size);' >> fuzz_harness.c && \
    echo '    http_parser_init(&parser, HTTP_BOTH);' >> fuzz_harness.c && \
    echo '    http_parser_execute(&parser, &settings, input, input_size);' >> fuzz_harness.c && \
    echo '    free(input);' >> fuzz_harness.c && \
    echo '    return 0;' >> fuzz_harness.c && \
    echo '}' >> fuzz_harness.c

RUN AFL_LLVM_CMPLOG=1 afl-clang-lto \
    -O2 \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o http_parser_fuzz \
    fuzz_harness.c http_parser.c

RUN cp http_parser_fuzz /out/http_parser_fuzz.cmplog

# Copy fuzzing resources
COPY dataset/http-parser/fuzz/dict /out/dict
COPY dataset/http-parser/fuzz/in /out/in
COPY dataset/http-parser/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/http-parser/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/http_parser_fuzz /out/http_parser_fuzz.cmplog && \
    file /out/http_parser_fuzz

CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing http-parser'"]
