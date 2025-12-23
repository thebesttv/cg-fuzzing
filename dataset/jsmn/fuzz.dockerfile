FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
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
RUN echo "project: jsmn" > /work/proj && \
    echo "version: 1.1.0" >> /work/proj && \
    echo "source: https://github.com/zserge/jsmn/archive/refs/tags/v1.1.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/zserge/jsmn/archive/refs/tags/v1.1.0.tar.gz && \
    tar -xzf v1.1.0.tar.gz && \
    rm v1.1.0.tar.gz && \
    cp -a jsmn-1.1.0 build-fuzz && \
    cp -a jsmn-1.1.0 build-cmplog && \
    cp -a jsmn-1.1.0 build-cov && \
    cp -a jsmn-1.1.0 build-uftrace && \
    rm -rf jsmn-1.1.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN afl-clang-lto \
    -O2 \
    -DJSMN_PARENT_LINKS \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o jsondump \
    example/jsondump.c

WORKDIR /work
RUN ln -s build-fuzz/jsondump bin-fuzz && \
    echo '{}' | /work/bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto \
    -O2 \
    -DJSMN_PARENT_LINKS \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o jsondump \
    example/jsondump.c

WORKDIR /work
RUN ln -s build-cmplog/jsondump bin-cmplog && \
    echo '{}' | /work/bin-cmplog

# Copy fuzzing resources
COPY jsmn/fuzz/dict /work/dict
COPY jsmn/fuzz/in /work/in
COPY jsmn/fuzz/fuzz.sh /work/fuzz.sh
COPY jsmn/fuzz/whatsup.sh /work/whatsup.sh
COPY jsmn/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN clang \
    -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -DJSMN_PARENT_LINKS \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o jsondump \
    example/jsondump.c

WORKDIR /work
RUN ln -s build-cov/jsondump bin-cov && \
    echo '{}' | /work/bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN clang \
    -g -O0 -pg -fno-omit-frame-pointer \
    -DJSMN_PARENT_LINKS \
    -I. \
    -pg -Wl,--allow-multiple-definition \
    -o jsondump \
    example/jsondump.c

WORKDIR /work
RUN ln -s build-uftrace/jsondump bin-uftrace && \
    echo '{}' | /work/bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
