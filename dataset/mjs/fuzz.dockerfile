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
RUN echo "project: mjs" > /work/proj && \
    echo "version: 2.20.0" >> /work/proj && \
    echo "source: https://github.com/cesanta/mjs/archive/refs/tags/2.20.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/cesanta/mjs/archive/refs/tags/2.20.0.tar.gz && \
    tar -xzf 2.20.0.tar.gz && \
    rm 2.20.0.tar.gz && \
    cp -a mjs-2.20.0 build-fuzz && \
    cp -a mjs-2.20.0 build-cmplog && \
    cp -a mjs-2.20.0 build-cov && \
    cp -a mjs-2.20.0 build-uftrace && \
    rm -rf mjs-2.20.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir -p build && \
    afl-clang-lto -DMJS_MAIN -I. -Isrc \
    -O2 \
    mjs.c -lm \
    -static -Wl,--allow-multiple-definition \
    -o build/mjs

WORKDIR /work
RUN ln -s build-fuzz/build/mjs bin-fuzz && \
    /work/bin-fuzz -e 'print(1+1)'

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir -p build && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -DMJS_MAIN -I. -Isrc \
    -O2 \
    mjs.c -lm \
    -static -Wl,--allow-multiple-definition \
    -o build/mjs

WORKDIR /work
RUN ln -s build-cmplog/build/mjs bin-cmplog && \
    /work/bin-cmplog -e 'print(1+1)'

# Copy fuzzing resources
COPY mjs/fuzz/dict /work/dict
COPY mjs/fuzz/in /work/in
COPY mjs/fuzz/fuzz.sh /work/fuzz.sh
COPY mjs/fuzz/whatsup.sh /work/whatsup.sh
COPY mjs/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY mjs/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY mjs/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir -p build && \
    clang -DMJS_MAIN -I. -Isrc \
    -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    mjs.c -lm \
    -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition \
    -o build/mjs

WORKDIR /work
RUN ln -s build-cov/build/mjs bin-cov && \
    /work/bin-cov -e 'print(1+1)' && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir -p install && \
    clang -DMJS_MAIN -I. -Isrc \
    -g -O0 -pg -fno-omit-frame-pointer \
    mjs.c -lm \
    -pg -Wl,--allow-multiple-definition \
    -o install/mjs

WORKDIR /work
RUN ln -s build-uftrace/install/mjs bin-uftrace && \
    /work/bin-uftrace -e 'print(1+1)' && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
