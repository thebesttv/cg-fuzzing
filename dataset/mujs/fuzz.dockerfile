FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libreadline-dev curl uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: mujs" > /work/proj && \
    echo "version: 1.3.8" >> /work/proj && \
    echo "source: https://github.com/ArtifexSoftware/mujs/archive/refs/tags/1.3.8.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/ArtifexSoftware/mujs/archive/refs/tags/1.3.8.tar.gz && \
    tar -xzf 1.3.8.tar.gz && \
    rm 1.3.8.tar.gz && \
    cp -a mujs-1.3.8 build-fuzz && \
    cp -a mujs-1.3.8 build-cmplog && \
    cp -a mujs-1.3.8 build-cov && \
    cp -a mujs-1.3.8 build-uftrace && \
    rm -rf mujs-1.3.8

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    build/release/libmujs.o && \
    afl-clang-lto -O2 -static -Wl,--allow-multiple-definition \
    -o build/release/mujs main.c build/release/libmujs.o -lm

WORKDIR /work
RUN ln -s build-fuzz/build/release/mujs bin-fuzz && \
    test -x /work/bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    build/release/libmujs.o && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -static -Wl,--allow-multiple-definition \
    -o build/release/mujs main.c build/release/libmujs.o -lm

WORKDIR /work
RUN ln -s build-cmplog/build/release/mujs bin-cmplog && \
    test -x /work/bin-cmplog

# Copy fuzzing resources
COPY mujs/fuzz/dict /work/dict
COPY mujs/fuzz/in /work/in
COPY mujs/fuzz/fuzz.sh /work/fuzz.sh
COPY mujs/fuzz/whatsup.sh /work/whatsup.sh
COPY mujs/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY mujs/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY mujs/fuzz/collect-branch.py /work/collect-branch.py
COPY mujs/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make -j$(nproc) \
    CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    build/release/libmujs.o && \
    clang -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -static -Wl,--allow-multiple-definition \
    -o build/release/mujs main.c build/release/libmujs.o -lm

WORKDIR /work
RUN ln -s build-cov/build/release/mujs bin-cov && \
    test -x /work/bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make -j$(nproc) \
    CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    build/release/libmujs.o && \
    clang -g -O0 -pg -fno-omit-frame-pointer \
    -Wl,--allow-multiple-definition \
    -o build/release/mujs main.c build/release/libmujs.o -lm

WORKDIR /work
RUN ln -s build-uftrace/build/release/mujs bin-uftrace && \
    test -x /work/bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
