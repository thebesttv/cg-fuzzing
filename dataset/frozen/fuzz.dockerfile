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
RUN echo "project: frozen" > /work/proj && \
    echo "version: 1.7" >> /work/proj && \
    echo "source: https://github.com/cesanta/frozen/archive/refs/tags/1.7.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/cesanta/frozen/archive/refs/tags/1.7.tar.gz && \
    tar -xzf 1.7.tar.gz && \
    rm 1.7.tar.gz && \
    cp -a frozen-1.7 build-fuzz && \
    cp -a frozen-1.7 build-cmplog && \
    cp -a frozen-1.7 build-cov && \
    cp -a frozen-1.7 build-uftrace && \
    rm -rf frozen-1.7

# Copy the fuzzing harness to all build directories
COPY frozen/fuzz_json.c /work/build-fuzz/
COPY frozen/fuzz_json.c /work/build-cmplog/
COPY frozen/fuzz_json.c /work/build-cov/
COPY frozen/fuzz_json.c /work/build-uftrace/

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN afl-clang-lto -O2 -static -Wl,--allow-multiple-definition \
    -o fuzz_json fuzz_json.c frozen.c -lm

WORKDIR /work
RUN ln -s build-fuzz/fuzz_json bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -static -Wl,--allow-multiple-definition \
    -o fuzz_json fuzz_json.c frozen.c -lm

WORKDIR /work
RUN ln -s build-cmplog/fuzz_json bin-cmplog

# Copy fuzzing resources
COPY frozen/fuzz/dict /work/dict
COPY frozen/fuzz/in /work/in
COPY frozen/fuzz/fuzz.sh /work/fuzz.sh
COPY frozen/fuzz/whatsup.sh /work/whatsup.sh
COPY frozen/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY frozen/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY frozen/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition \
    -o fuzz_json fuzz_json.c frozen.c -lm

WORKDIR /work
RUN ln -s build-cov/fuzz_json bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN clang -g -O0 -pg -fno-omit-frame-pointer \
    -pg -Wl,--allow-multiple-definition \
    -o fuzz_json fuzz_json.c frozen.c -lm

WORKDIR /work
RUN ln -s build-uftrace/fuzz_json bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
