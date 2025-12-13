FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: inih" > /work/proj && \
    echo "version: r62" >> /work/proj && \
    echo "source: https://github.com/benhoyt/inih/archive/refs/tags/r62.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/benhoyt/inih/archive/refs/tags/r62.tar.gz && \
    tar -xzf r62.tar.gz && \
    rm r62.tar.gz && \
    cp -a inih-r62 build-fuzz && \
    cp -a inih-r62 build-cmplog && \
    cp -a inih-r62 build-cov && \
    cp -a inih-r62 build-uftrace && \
    rm -rf inih-r62

# Create fuzzing harness in all build directories
RUN for dir in build-fuzz build-cmplog build-cov build-uftrace; do \
      cd /work/$dir && \
      printf '%s\n' \
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
        '}' > ini_fuzz.c; \
    done

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN afl-clang-lto -O2 -o ini_fuzz ini_fuzz.c ini.c \
    -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-fuzz/ini_fuzz bin-fuzz && \
    echo '[section]' > /tmp/test.ini && \
    echo 'key=value' >> /tmp/test.ini && \
    /work/bin-fuzz /tmp/test.ini

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -o ini_fuzz ini_fuzz.c ini.c \
    -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-cmplog/ini_fuzz bin-cmplog && \
    /work/bin-cmplog /tmp/test.ini

# Copy fuzzing resources
COPY inih/fuzz/dict /work/dict
COPY inih/fuzz/in /work/in
COPY inih/fuzz/fuzz.sh /work/fuzz.sh
COPY inih/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN clang \
    -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -o ini_fuzz ini_fuzz.c ini.c \
    -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-cov/ini_fuzz bin-cov && \
    /work/bin-cov /tmp/test.ini && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN clang \
    -g -O0 -pg -fno-omit-frame-pointer \
    -o ini_fuzz ini_fuzz.c ini.c \
    -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-uftrace/ini_fuzz bin-uftrace && \
    /work/bin-uftrace /tmp/test.ini && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
