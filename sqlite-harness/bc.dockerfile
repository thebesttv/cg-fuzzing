FROM svftools/svf:latest

# Install wllvm using pipx and build dependencies
RUN apt-get update && \
    apt-get install -y pipx file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract SQLite version-3.51.0
WORKDIR /home/SVF-tools
RUN wget https://github.com/sqlite/sqlite/archive/refs/tags/version-3.51.0.tar.gz && \
    tar -xzf version-3.51.0.tar.gz && \
    rm version-3.51.0.tar.gz

WORKDIR /home/SVF-tools/sqlite-version-3.51.0

# Configure SQLite with static linking and WLLVM
# Disable TCL extension and shared libraries
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-tcl --disable-shared --enable-static

# Build only the sqlite3 library (we need libsqlite3.a for the harness)
RUN make sqlite3.c sqlite3.h -j$(nproc)

# Create a main wrapper for the OSS-Fuzz harness
# The ossfuzz.c harness uses LLVMFuzzerTestOneInput which needs a main() to be linked
RUN printf '%s\n' \
    '#include <stdio.h>' \
    '#include <stdlib.h>' \
    '#include <stdint.h>' \
    '' \
    'extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);' \
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

# Compile SQLite amalgamation (sqlite3.c contains the entire SQLite library)
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -c sqlite3.c -o sqlite3.o \
    -DSQLITE_OMIT_LOAD_EXTENSION

# Compile the OSS-Fuzz harness (test/ossfuzz.c)
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -c test/ossfuzz.c -o ossfuzz.o \
    -I.

# Compile the main wrapper
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -c fuzz_main.c -o fuzz_main.o

# Link harness with SQLite and main wrapper (static linking)
RUN wllvm -g -O0 -Xclang -disable-llvm-passes \
    -static -Wl,--allow-multiple-definition \
    fuzz_main.o ossfuzz.o sqlite3.o \
    -lpthread -lm -ldl \
    -o sqlite_ossfuzz

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc sqlite_ossfuzz && \
    mv sqlite_ossfuzz.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
