FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download inih r62 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/benhoyt/inih/archive/refs/tags/r62.tar.gz && \
    tar -xzf r62.tar.gz && \
    rm r62.tar.gz

WORKDIR /src/inih-r62

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

# Build the harness with afl-clang-lto for fuzzing
RUN afl-clang-lto -O2 -o ini_fuzz ini_fuzz.c ini.c \
    -static -Wl,--allow-multiple-definition

# Install the binary
RUN cp ini_fuzz /out/ini_fuzz

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf inih-r62 && \
    wget https://github.com/benhoyt/inih/archive/refs/tags/r62.tar.gz && \
    tar -xzf r62.tar.gz && \
    rm r62.tar.gz

WORKDIR /src/inih-r62

# Create the harness again
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

# Build CMPLOG version
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -o ini_fuzz.cmplog ini_fuzz.c ini.c \
    -static -Wl,--allow-multiple-definition

# Install CMPLOG binary
RUN cp ini_fuzz.cmplog /out/ini_fuzz.cmplog

# Copy fuzzing resources
COPY inih/fuzz/dict /out/dict
COPY inih/fuzz/in /out/in
COPY inih/fuzz/fuzz.sh /out/fuzz.sh
COPY inih/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/ini_fuzz /out/ini_fuzz.cmplog && \
    file /out/ini_fuzz

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing inih'"]
