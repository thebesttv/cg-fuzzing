FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract picohttpparser (latest commit from master)
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/h2o/picohttpparser/archive/refs/heads/master.tar.gz && \
    tar -xzf master.tar.gz && \
    rm master.tar.gz

WORKDIR /home/SVF-tools/picohttpparser-master

# Create a fuzzing harness that reads HTTP data from file
RUN echo '#include <stdio.h>' > fuzz_harness.c && \
    echo '#include <stdlib.h>' >> fuzz_harness.c && \
    echo '#include <string.h>' >> fuzz_harness.c && \
    echo '#include "picohttpparser.h"' >> fuzz_harness.c && \
    echo '#define MAX_INPUT_SIZE (1024 * 1024)' >> fuzz_harness.c && \
    echo '#define MAX_HEADERS 100' >> fuzz_harness.c && \
    echo 'int main(int argc, char *argv[]) {' >> fuzz_harness.c && \
    echo '    FILE *f;' >> fuzz_harness.c && \
    echo '    char *input = NULL;' >> fuzz_harness.c && \
    echo '    size_t input_size;' >> fuzz_harness.c && \
    echo '    const char *method, *path, *msg;' >> fuzz_harness.c && \
    echo '    size_t method_len, path_len, msg_len, num_headers;' >> fuzz_harness.c && \
    echo '    int minor_version, status;' >> fuzz_harness.c && \
    echo '    struct phr_header headers[MAX_HEADERS];' >> fuzz_harness.c && \
    echo '    struct phr_chunked_decoder decoder;' >> fuzz_harness.c && \
    echo '    size_t bufsz;' >> fuzz_harness.c && \
    echo '    char *buf_copy;' >> fuzz_harness.c && \
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
    echo '    /* Parse as HTTP request */' >> fuzz_harness.c && \
    echo '    num_headers = MAX_HEADERS;' >> fuzz_harness.c && \
    echo '    phr_parse_request(input, input_size, &method, &method_len, &path, &path_len, &minor_version, headers, &num_headers, 0);' >> fuzz_harness.c && \
    echo '    /* Parse as HTTP response */' >> fuzz_harness.c && \
    echo '    num_headers = MAX_HEADERS;' >> fuzz_harness.c && \
    echo '    phr_parse_response(input, input_size, &minor_version, &status, &msg, &msg_len, headers, &num_headers, 0);' >> fuzz_harness.c && \
    echo '    /* Parse as headers only */' >> fuzz_harness.c && \
    echo '    num_headers = MAX_HEADERS;' >> fuzz_harness.c && \
    echo '    phr_parse_headers(input, input_size, headers, &num_headers, 0);' >> fuzz_harness.c && \
    echo '    /* Decode chunked encoding */' >> fuzz_harness.c && \
    echo '    buf_copy = (char *)malloc(input_size);' >> fuzz_harness.c && \
    echo '    if (buf_copy) {' >> fuzz_harness.c && \
    echo '        memcpy(buf_copy, input, input_size);' >> fuzz_harness.c && \
    echo '        memset(&decoder, 0, sizeof(decoder));' >> fuzz_harness.c && \
    echo '        bufsz = input_size;' >> fuzz_harness.c && \
    echo '        phr_decode_chunked(&decoder, buf_copy, &bufsz);' >> fuzz_harness.c && \
    echo '        free(buf_copy);' >> fuzz_harness.c && \
    echo '    }' >> fuzz_harness.c && \
    echo '    free(input);' >> fuzz_harness.c && \
    echo '    return 0;' >> fuzz_harness.c && \
    echo '}' >> fuzz_harness.c

# Build picohttpparser with WLLVM
RUN wllvm \
    -g -O0 -Xclang -disable-llvm-passes \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o picohttpparser_fuzz \
    fuzz_harness.c picohttpparser.c

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc picohttpparser_fuzz && \
    mv picohttpparser_fuzz.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
