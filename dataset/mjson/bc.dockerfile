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

# Download and extract mjson v1.2.7
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/cesanta/mjson/archive/refs/tags/1.2.7.tar.gz && \
    tar -xzf 1.2.7.tar.gz && \
    rm 1.2.7.tar.gz

WORKDIR /home/SVF-tools/mjson-1.2.7

# Create a fuzzing harness that reads JSON from file and parses it
RUN echo '#include <stdio.h>' > fuzz_harness.c && \
    echo '#include <stdlib.h>' >> fuzz_harness.c && \
    echo '#include <string.h>' >> fuzz_harness.c && \
    echo '#include "src/mjson.h"' >> fuzz_harness.c && \
    echo '#define MAX_INPUT_SIZE (1024 * 1024)' >> fuzz_harness.c && \
    echo 'int main(int argc, char *argv[]) {' >> fuzz_harness.c && \
    echo '    FILE *f;' >> fuzz_harness.c && \
    echo '    char *input = NULL;' >> fuzz_harness.c && \
    echo '    size_t input_size;' >> fuzz_harness.c && \
    echo '    double dval;' >> fuzz_harness.c && \
    echo '    int ival;' >> fuzz_harness.c && \
    echo '    int bval;' >> fuzz_harness.c && \
    echo '    char buf[256];' >> fuzz_harness.c && \
    echo '    const char *p;' >> fuzz_harness.c && \
    echo '    int n;' >> fuzz_harness.c && \
    echo '    if (argc < 2) { fprintf(stderr, "Usage: %s <input_file>\\n", argv[0]); return 1; }' >> fuzz_harness.c && \
    echo '    f = fopen(argv[1], "rb");' >> fuzz_harness.c && \
    echo '    if (!f) { fprintf(stderr, "Cannot open file: %s\\n", argv[1]); return 1; }' >> fuzz_harness.c && \
    echo '    fseek(f, 0, SEEK_END);' >> fuzz_harness.c && \
    echo '    input_size = ftell(f);' >> fuzz_harness.c && \
    echo '    rewind(f);' >> fuzz_harness.c && \
    echo '    if (input_size == 0 || input_size > MAX_INPUT_SIZE) { fclose(f); return 0; }' >> fuzz_harness.c && \
    echo '    input = (char *)malloc(input_size + 1);' >> fuzz_harness.c && \
    echo '    if (!input) { fclose(f); return 1; }' >> fuzz_harness.c && \
    echo '    if (fread(input, 1, input_size, f) != input_size) { free(input); fclose(f); return 1; }' >> fuzz_harness.c && \
    echo '    fclose(f);' >> fuzz_harness.c && \
    echo '    input[input_size] = 0;' >> fuzz_harness.c && \
    echo '    mjson_get_number(input, (int)input_size, "$", &dval);' >> fuzz_harness.c && \
    echo '    mjson_get_bool(input, (int)input_size, "$", &bval);' >> fuzz_harness.c && \
    echo '    mjson_get_string(input, (int)input_size, "$", buf, sizeof(buf));' >> fuzz_harness.c && \
    echo '    mjson_find(input, (int)input_size, "$", &p, &n);' >> fuzz_harness.c && \
    echo '    mjson_get_number(input, (int)input_size, "$.a", &dval);' >> fuzz_harness.c && \
    echo '    mjson_get_string(input, (int)input_size, "$.b", buf, sizeof(buf));' >> fuzz_harness.c && \
    echo '    mjson_find(input, (int)input_size, "$.c[0]", &p, &n);' >> fuzz_harness.c && \
    echo '    free(input);' >> fuzz_harness.c && \
    echo '    return 0;' >> fuzz_harness.c && \
    echo '}' >> fuzz_harness.c

# Build mjson with WLLVM (single file library)
RUN wllvm \
    -g -O0 -Xclang -disable-llvm-passes \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o mjson_fuzz \
    fuzz_harness.c src/mjson.c

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc mjson_fuzz && \
    mv mjson_fuzz.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
