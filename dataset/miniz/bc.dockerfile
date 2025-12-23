FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract miniz v3.1.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: miniz" > /work/proj && \
    echo "version: 3.1.0" >> /work/proj && \
    echo "source: https://github.com/richgel999/miniz/archive/refs/tags/3.1.0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/richgel999/miniz/archive/refs/tags/3.1.0.tar.gz && \
    tar -xzf 3.1.0.tar.gz && \
    mv 3.1.0 build && \
    rm 3.1.0.tar.gz

WORKDIR /work/build

# Build with CMake to generate export header and library
RUN mkdir build && cd build && \
    CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    cmake .. \
        -DCMAKE_C_COMPILER=wllvm \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    make -j$(nproc)

# Create a simple fuzzing harness that reads from file and decompresses
WORKDIR /work/build
RUN echo '#include <stdio.h>' > fuzz_harness.c && \
    echo '#include <stdlib.h>' >> fuzz_harness.c && \
    echo '#include <string.h>' >> fuzz_harness.c && \
    echo '#include "miniz.h"' >> fuzz_harness.c && \
    echo '#define MAX_INPUT_SIZE (1024 * 1024)' >> fuzz_harness.c && \
    echo 'int main(int argc, char *argv[]) {' >> fuzz_harness.c && \
    echo '    FILE *f;' >> fuzz_harness.c && \
    echo '    unsigned char *input = NULL;' >> fuzz_harness.c && \
    echo '    unsigned char *output = NULL;' >> fuzz_harness.c && \
    echo '    size_t input_size;' >> fuzz_harness.c && \
    echo '    mz_ulong output_size;' >> fuzz_harness.c && \
    echo '    int result;' >> fuzz_harness.c && \
    echo '    if (argc < 2) { fprintf(stderr, "Usage: %s <input_file>\\n", argv[0]); return 1; }' >> fuzz_harness.c && \
    echo '    f = fopen(argv[1], "rb");' >> fuzz_harness.c && \
    echo '    if (!f) { fprintf(stderr, "Cannot open file: %s\\n", argv[1]); return 1; }' >> fuzz_harness.c && \
    echo '    fseek(f, 0, SEEK_END);' >> fuzz_harness.c && \
    echo '    input_size = ftell(f);' >> fuzz_harness.c && \
    echo '    rewind(f);' >> fuzz_harness.c && \
    echo '    if (input_size == 0 || input_size > MAX_INPUT_SIZE) { fclose(f); return 0; }' >> fuzz_harness.c && \
    echo '    input = (unsigned char *)malloc(input_size);' >> fuzz_harness.c && \
    echo '    if (!input) { fclose(f); return 1; }' >> fuzz_harness.c && \
    echo '    if (fread(input, 1, input_size, f) != input_size) { free(input); fclose(f); return 1; }' >> fuzz_harness.c && \
    echo '    fclose(f);' >> fuzz_harness.c && \
    echo '    output_size = (mz_ulong)(input_size * 10 + 1024);' >> fuzz_harness.c && \
    echo '    output = (unsigned char *)malloc(output_size);' >> fuzz_harness.c && \
    echo '    if (!output) { free(input); return 1; }' >> fuzz_harness.c && \
    echo '    result = uncompress(output, &output_size, input, (mz_ulong)input_size);' >> fuzz_harness.c && \
    echo '    (void)result;' >> fuzz_harness.c && \
    echo '    {' >> fuzz_harness.c && \
    echo '        mz_stream stream;' >> fuzz_harness.c && \
    echo '        memset(&stream, 0, sizeof(stream));' >> fuzz_harness.c && \
    echo '        stream.next_in = input;' >> fuzz_harness.c && \
    echo '        stream.avail_in = (mz_uint32)input_size;' >> fuzz_harness.c && \
    echo '        stream.next_out = output;' >> fuzz_harness.c && \
    echo '        stream.avail_out = (mz_uint32)(input_size * 10 + 1024);' >> fuzz_harness.c && \
    echo '        if (inflateInit(&stream) == MZ_OK) {' >> fuzz_harness.c && \
    echo '            inflate(&stream, MZ_FINISH);' >> fuzz_harness.c && \
    echo '            inflateEnd(&stream);' >> fuzz_harness.c && \
    echo '        }' >> fuzz_harness.c && \
    echo '    }' >> fuzz_harness.c && \
    echo '    free(output);' >> fuzz_harness.c && \
    echo '    free(input);' >> fuzz_harness.c && \
    echo '    return 0;' >> fuzz_harness.c && \
    echo '}' >> fuzz_harness.c

# Build the harness with the library
RUN wllvm \
    -g -O0 -Xclang -disable-llvm-passes \
    -I. -Ibuild \
    -static -Wl,--allow-multiple-definition \
    -o miniz_fuzz \
    fuzz_harness.c build/libminiz.a

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc miniz_fuzz && \
    mv miniz_fuzz.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
