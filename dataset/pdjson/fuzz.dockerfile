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
RUN echo "project: pdjson" > /work/proj && \
    echo "version: master" >> /work/proj && \
    echo "source: https://github.com/skeeto/pdjson/archive/refs/heads/master.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/skeeto/pdjson/archive/refs/heads/master.tar.gz -O pdjson.tar.gz && \
    tar -xzf pdjson.tar.gz && \
    rm pdjson.tar.gz && \
    cp -a pdjson-master build-fuzz && \
    cp -a pdjson-master build-cmplog && \
    cp -a pdjson-master build-cov && \
    cp -a pdjson-master build-uftrace && \
    rm -rf pdjson-master

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN afl-clang-lto -c -O2 -std=c99 pdjson.c -o pdjson.o && \
    afl-clang-lto -c -O2 -std=c99 tests/pretty.c -o tests/pretty.o && \
    afl-clang-lto -O2 -static -Wl,--allow-multiple-definition -o pretty tests/pretty.o pdjson.o

WORKDIR /work
RUN ln -s build-fuzz/pretty bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -c -O2 -std=c99 pdjson.c -o pdjson.o && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -c -O2 -std=c99 tests/pretty.c -o tests/pretty.o && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -static -Wl,--allow-multiple-definition -o pretty tests/pretty.o pdjson.o

WORKDIR /work
RUN ln -s build-cmplog/pretty bin-cmplog

# Copy fuzzing resources
COPY pdjson/fuzz/dict /work/dict
COPY pdjson/fuzz/in /work/in
COPY pdjson/fuzz/fuzz.sh /work/fuzz.sh
COPY pdjson/fuzz/whatsup.sh /work/whatsup.sh
COPY pdjson/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY pdjson/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY pdjson/fuzz/collect-branch.py /work/collect-branch.py
COPY pdjson/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN clang -c -g -O0 -fprofile-instr-generate -fcoverage-mapping -std=c99 pdjson.c -o pdjson.o && \
    clang -c -g -O0 -fprofile-instr-generate -fcoverage-mapping -std=c99 tests/pretty.c -o tests/pretty.o && \
    clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition -o pretty tests/pretty.o pdjson.o

WORKDIR /work
RUN ln -s build-cov/pretty bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN clang -c -g -O0 -pg -fno-omit-frame-pointer -std=c99 pdjson.c -o pdjson.o && \
    clang -c -g -O0 -pg -fno-omit-frame-pointer -std=c99 tests/pretty.c -o tests/pretty.o && \
    clang -g -O0 -pg -fno-omit-frame-pointer -Wl,--allow-multiple-definition -o pretty tests/pretty.o pdjson.o

WORKDIR /work
RUN ln -s build-uftrace/pretty bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
