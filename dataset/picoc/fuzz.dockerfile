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
RUN echo "project: picoc" > /work/proj && \
    echo "version: 3.2.2" >> /work/proj && \
    echo "source: https://github.com/jpoirier/picoc/archive/refs/tags/v3.2.2.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/jpoirier/picoc/archive/refs/tags/v3.2.2.tar.gz && \
    tar -xzf v3.2.2.tar.gz && \
    rm v3.2.2.tar.gz && \
    cp -a picoc-3.2.2 build-fuzz && \
    cp -a picoc-3.2.2 build-cmplog && \
    cp -a picoc-3.2.2 build-cov && \
    cp -a picoc-3.2.2 build-uftrace && \
    rm -rf picoc-3.2.2

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN sed -i 's/#define USE_READLINE/\/\/ #define USE_READLINE/' platform.h && \
    make CC=afl-clang-lto \
    CFLAGS="-Wall -O2 -std=gnu11 -pedantic -DUNIX_HOST" \
    LIBS="-lm -static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/picoc bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN sed -i 's/#define USE_READLINE/\/\/ #define USE_READLINE/' platform.h && \
    AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    CFLAGS="-Wall -O2 -std=gnu11 -pedantic -DUNIX_HOST" \
    LIBS="-lm -static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/picoc bin-cmplog

# Copy fuzzing resources
COPY picoc/fuzz/dict /work/dict
COPY picoc/fuzz/in /work/in
COPY picoc/fuzz/fuzz.sh /work/fuzz.sh
COPY picoc/fuzz/whatsup.sh /work/whatsup.sh
COPY picoc/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY picoc/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY picoc/fuzz/collect-branch.py /work/collect-branch.py
COPY picoc/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN sed -i 's/#define USE_READLINE/\/\/ #define USE_READLINE/' platform.h && \
    make CC=clang \
    CFLAGS="-Wall -g -O0 -fprofile-instr-generate -fcoverage-mapping -std=gnu11 -pedantic -DUNIX_HOST" \
    LIBS="-lm -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/picoc bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN sed -i 's/#define USE_READLINE/\/\/ #define USE_READLINE/' platform.h && \
    make CC=clang \
    CFLAGS="-Wall -g -O0 -pg -fno-omit-frame-pointer -std=gnu11 -pedantic -DUNIX_HOST" \
    LIBS="-lm -pg -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/picoc bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
