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
RUN echo "project: tinyexpr" > /work/proj && \
    echo "version: master" >> /work/proj && \
    echo "source: https://github.com/codeplea/tinyexpr/archive/refs/heads/master.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/codeplea/tinyexpr/archive/refs/heads/master.tar.gz -O tinyexpr.tar.gz && \
    tar -xzf tinyexpr.tar.gz && \
    rm tinyexpr.tar.gz && \
    cp -a tinyexpr-master build-fuzz && \
    cp -a tinyexpr-master build-cmplog && \
    cp -a tinyexpr-master build-cov && \
    cp -a tinyexpr-master build-uftrace && \
    rm -rf tinyexpr-master

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN afl-clang-lto -c -O2 -Wall tinyexpr.c -o tinyexpr.o && \
    afl-clang-lto -c -O2 -Wall repl.c -o repl.o && \
    afl-clang-lto -O2 -static -Wl,--allow-multiple-definition -o repl repl.o tinyexpr.o -lm

WORKDIR /work
RUN ln -s build-fuzz/repl bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -c -O2 -Wall tinyexpr.c -o tinyexpr.o && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -c -O2 -Wall repl.c -o repl.o && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -static -Wl,--allow-multiple-definition -o repl repl.o tinyexpr.o -lm

WORKDIR /work
RUN ln -s build-cmplog/repl bin-cmplog

# Copy fuzzing resources
COPY tinyexpr/fuzz/dict /work/dict
COPY tinyexpr/fuzz/in /work/in
COPY tinyexpr/fuzz/fuzz.sh /work/fuzz.sh
COPY tinyexpr/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN clang -c -g -O0 -fprofile-instr-generate -fcoverage-mapping -Wall tinyexpr.c -o tinyexpr.o && \
    clang -c -g -O0 -fprofile-instr-generate -fcoverage-mapping -Wall repl.c -o repl.o && \
    clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition -o repl repl.o tinyexpr.o -lm

WORKDIR /work
RUN ln -s build-cov/repl bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN clang -c -g -O0 -pg -fno-omit-frame-pointer -Wall tinyexpr.c -o tinyexpr.o && \
    clang -c -g -O0 -pg -fno-omit-frame-pointer -Wall repl.c -o repl.o && \
    clang -g -O0 -pg -fno-omit-frame-pointer -Wl,--allow-multiple-definition -o repl repl.o tinyexpr.o -lm

WORKDIR /work
RUN ln -s build-uftrace/repl bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
