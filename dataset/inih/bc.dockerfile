FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download inih r62

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: inih" > /work/proj && \
    echo "version: unknown" >> /work/proj && \
    echo "source: https://github.com/benhoyt/inih/archive/refs/tags/r62.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/benhoyt/inih/archive/refs/tags/r62.tar.gz && \
    tar -xzf r62.tar.gz && \
    mv r62 build && \
    rm r62.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create a simple fuzzing harness that reads INI file from argument
RUN printf '%s\n' \
    '#include <stdio.h>' \
    '#include "ini.h"' \
    '' \
    'static int handler(void* user, const char* section, const char* name, const char* value) {' \
    '    (void)user;' \
    '    (void)section;' \
    '    (void)name;' \
    '    (void)value;' \
    '    return 1;' \
    '}' \
    '' \
    'int main(int argc, char* argv[]) {' \
    '    if (argc < 2) {' \
    '        return 1;' \
    '    }' \
    '    ini_parse(argv[1], handler, NULL);' \
    '    return 0;' \
    '}' > ini_fuzz.c

# Build the harness with WLLVM
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -o ini_fuzz ini_fuzz.c ini.c \
    -static -Wl,--allow-multiple-definition

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc ini_fuzz && \
    mv ini_fuzz.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
