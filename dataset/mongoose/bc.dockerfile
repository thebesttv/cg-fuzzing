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

# Download and extract mongoose 7.20
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/cesanta/mongoose/archive/refs/tags/7.20.tar.gz && \
    tar -xzf 7.20.tar.gz && \
    rm 7.20.tar.gz

WORKDIR /home/SVF-tools/mongoose-7.20

# Create a fuzzing harness that reads HTTP data from file and parses it
# This exercises the HTTP parsing functionality without needing network
RUN echo '#include <stdio.h>' > fuzz_harness.c && \
    echo '#include <stdlib.h>' >> fuzz_harness.c && \
    echo '#include <string.h>' >> fuzz_harness.c && \
    echo '#include "mongoose.h"' >> fuzz_harness.c && \
    echo '' >> fuzz_harness.c && \
    echo '#define MAX_INPUT_SIZE (1024 * 1024)' >> fuzz_harness.c && \
    echo '' >> fuzz_harness.c && \
    echo 'int main(int argc, char *argv[]) {' >> fuzz_harness.c && \
    echo '    FILE *f;' >> fuzz_harness.c && \
    echo '    char *input = NULL;' >> fuzz_harness.c && \
    echo '    size_t input_size;' >> fuzz_harness.c && \
    echo '    struct mg_http_message hm;' >> fuzz_harness.c && \
    echo '    struct mg_str body;' >> fuzz_harness.c && \
    echo '' >> fuzz_harness.c && \
    echo '    if (argc < 2) {' >> fuzz_harness.c && \
    echo '        fprintf(stderr, "Usage: %s <input_file>\\n", argv[0]);' >> fuzz_harness.c && \
    echo '        return 1;' >> fuzz_harness.c && \
    echo '    }' >> fuzz_harness.c && \
    echo '' >> fuzz_harness.c && \
    echo '    f = fopen(argv[1], "rb");' >> fuzz_harness.c && \
    echo '    if (!f) {' >> fuzz_harness.c && \
    echo '        fprintf(stderr, "Cannot open file: %s\\n", argv[1]);' >> fuzz_harness.c && \
    echo '        return 1;' >> fuzz_harness.c && \
    echo '    }' >> fuzz_harness.c && \
    echo '' >> fuzz_harness.c && \
    echo '    fseek(f, 0, SEEK_END);' >> fuzz_harness.c && \
    echo '    input_size = ftell(f);' >> fuzz_harness.c && \
    echo '    rewind(f);' >> fuzz_harness.c && \
    echo '' >> fuzz_harness.c && \
    echo '    if (input_size == 0 || input_size > MAX_INPUT_SIZE) {' >> fuzz_harness.c && \
    echo '        fclose(f);' >> fuzz_harness.c && \
    echo '        return 0;' >> fuzz_harness.c && \
    echo '    }' >> fuzz_harness.c && \
    echo '' >> fuzz_harness.c && \
    echo '    input = (char *)malloc(input_size + 1);' >> fuzz_harness.c && \
    echo '    if (!input) {' >> fuzz_harness.c && \
    echo '        fclose(f);' >> fuzz_harness.c && \
    echo '        return 1;' >> fuzz_harness.c && \
    echo '    }' >> fuzz_harness.c && \
    echo '' >> fuzz_harness.c && \
    echo '    if (fread(input, 1, input_size, f) != input_size) {' >> fuzz_harness.c && \
    echo '        free(input);' >> fuzz_harness.c && \
    echo '        fclose(f);' >> fuzz_harness.c && \
    echo '        return 1;' >> fuzz_harness.c && \
    echo '    }' >> fuzz_harness.c && \
    echo '    input[input_size] = 0;' >> fuzz_harness.c && \
    echo '    fclose(f);' >> fuzz_harness.c && \
    echo '' >> fuzz_harness.c && \
    echo '    /* Parse as HTTP request */' >> fuzz_harness.c && \
    echo '    memset(&hm, 0, sizeof(hm));' >> fuzz_harness.c && \
    echo '    mg_http_parse(input, input_size, &hm);' >> fuzz_harness.c && \
    echo '' >> fuzz_harness.c && \
    echo '    /* Try to get various headers */' >> fuzz_harness.c && \
    echo '    mg_http_get_header(&hm, "Content-Type");' >> fuzz_harness.c && \
    echo '    mg_http_get_header(&hm, "Content-Length");' >> fuzz_harness.c && \
    echo '    mg_http_get_header(&hm, "Host");' >> fuzz_harness.c && \
    echo '    mg_http_get_header(&hm, "User-Agent");' >> fuzz_harness.c && \
    echo '    mg_http_get_header(&hm, "Accept");' >> fuzz_harness.c && \
    echo '    mg_http_get_header(&hm, "Connection");' >> fuzz_harness.c && \
    echo '' >> fuzz_harness.c && \
    echo '    /* Try to get request body */' >> fuzz_harness.c && \
    echo '    body = hm.body;' >> fuzz_harness.c && \
    echo '    (void)body;' >> fuzz_harness.c && \
    echo '' >> fuzz_harness.c && \
    echo '    /* Try URL parsing */' >> fuzz_harness.c && \
    echo '    if (hm.uri.len > 0) {' >> fuzz_harness.c && \
    echo '        struct mg_str query = hm.query;' >> fuzz_harness.c && \
    echo '        (void)query;' >> fuzz_harness.c && \
    echo '    }' >> fuzz_harness.c && \
    echo '' >> fuzz_harness.c && \
    echo '    free(input);' >> fuzz_harness.c && \
    echo '    return 0;' >> fuzz_harness.c && \
    echo '}' >> fuzz_harness.c

# Build mongoose with WLLVM
# Mongoose is a single-file library, compile directly with the harness
RUN wllvm \
    -g -O0 -Xclang -disable-llvm-passes \
    -DMG_ENABLE_LINES=1 \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o mongoose_fuzz \
    fuzz_harness.c mongoose.c

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc mongoose_fuzz && \
    mv mongoose_fuzz.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
