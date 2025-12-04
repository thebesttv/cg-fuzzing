FROM svftools/svf:latest

# Install wllvm using pipx and build dependencies
RUN apt-get update && \
    apt-get install -y pipx file git autoconf automake libtool bison flex && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Clone jq from git (tag jq-1.8.1) to get harness files
# The release tarball doesn't include tests/jq_fuzz_*.c files
WORKDIR /home/SVF-tools
RUN git clone --depth 1 --branch jq-1.8.1 https://github.com/jqlang/jq.git jq-1.8.1

WORKDIR /home/SVF-tools/jq-1.8.1

# Initialize submodules (for oniguruma)
RUN git submodule init && git submodule update

# Run autoreconf to generate configure script
RUN autoreconf -fi

# Configure with static linking and WLLVM
# Use builtin oniguruma and enable all-static for static linking
# Note: Removed -Xclang -disable-llvm-passes from CXXFLAGS as it causes linker errors with C++ std library
RUN CC=wllvm \
    CXX=wllvm++ \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    CXXFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --with-oniguruma=builtin --disable-shared --enable-all-static

# Build jq library
RUN make -j$(nproc)

# Create a simple main wrapper for bitcode extraction
# The harness uses LLVMFuzzerTestOneInput which needs a main() to be linked
RUN printf '%s\n' \
    '#include <stdio.h>' \
    '#include <stdlib.h>' \
    '#include <stdint.h>' \
    '' \
    'extern int LLVMFuzzerTestOneInput(uint8_t *data, size_t size);' \
    '' \
    'int main(int argc, char **argv) {' \
    '    if (argc < 2) {' \
    '        fprintf(stderr, "Usage: %s <input_file>\\n", argv[0]);' \
    '        return 1;' \
    '    }' \
    '    FILE *f = fopen(argv[1], "rb");' \
    '    if (!f) {' \
    '        perror("fopen");' \
    '        return 1;' \
    '    }' \
    '    fseek(f, 0, SEEK_END);' \
    '    long size = ftell(f);' \
    '    fseek(f, 0, SEEK_SET);' \
    '    uint8_t *data = (uint8_t*)malloc(size);' \
    '    if (fread(data, 1, size, f) != (size_t)size) {' \
    '        perror("fread");' \
    '        return 1;' \
    '    }' \
    '    fclose(f);' \
    '    LLVMFuzzerTestOneInput(data, size);' \
    '    free(data);' \
    '    return 0;' \
    '}' > fuzz_main.c

# Compile the jq_fuzz_compile harness (tests jq_compile function)
# Using the C harness instead of C++ to avoid FuzzedDataProvider.h dependency
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -c tests/jq_fuzz_compile.c \
    -I./src -o ./jq_fuzz_compile.o

# Compile the main wrapper
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -c fuzz_main.c -o fuzz_main.o

# Link harness with jq library and main wrapper (static linking)
# Note: Removed -Xclang -disable-llvm-passes from wllvm++ as it causes linker errors with C++ std library
RUN wllvm++ -g -O0 \
    -static -Wl,--allow-multiple-definition \
    ./fuzz_main.o ./jq_fuzz_compile.o \
    ./.libs/libjq.a ./vendor/oniguruma/src/.libs/libonig.a \
    -o jq_fuzz_compile

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc jq_fuzz_compile && \
    mv jq_fuzz_compile.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
