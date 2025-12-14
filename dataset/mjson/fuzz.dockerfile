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
RUN echo "project: mjson" > /work/proj && \
    echo "version: 1.2.7" >> /work/proj && \
    echo "source: https://github.com/cesanta/mjson/archive/refs/tags/1.2.7.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/cesanta/mjson/archive/refs/tags/1.2.7.tar.gz && \
    tar -xzf 1.2.7.tar.gz && \
    rm 1.2.7.tar.gz && \
    cp -a mjson-1.2.7 build-fuzz && \
    cp -a mjson-1.2.7 build-cmplog && \
    cp -a mjson-1.2.7 build-cov && \
    cp -a mjson-1.2.7 build-uftrace && \
    rm -rf mjson-1.2.7

# Copy harness source to all build directories
COPY mjson/fuzz_harness.c /work/build-fuzz/
COPY mjson/fuzz_harness.c /work/build-cmplog/
COPY mjson/fuzz_harness.c /work/build-cov/
COPY mjson/fuzz_harness.c /work/build-uftrace/

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN afl-clang-lto -O2 -I. \
    -static -Wl,--allow-multiple-definition \
    -o mjson_fuzz fuzz_harness.c src/mjson.c

WORKDIR /work
RUN ln -s build-fuzz/mjson_fuzz bin-fuzz && \
    /work/bin-fuzz || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I. \
    -static -Wl,--allow-multiple-definition \
    -o mjson_fuzz fuzz_harness.c src/mjson.c

WORKDIR /work
RUN ln -s build-cmplog/mjson_fuzz bin-cmplog && \
    /work/bin-cmplog || true

# Copy fuzzing resources
COPY mjson/fuzz/dict /work/dict
COPY mjson/fuzz/in /work/in
COPY mjson/fuzz/fuzz.sh /work/fuzz.sh
COPY mjson/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -I. \
    -fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition \
    -o mjson_fuzz fuzz_harness.c src/mjson.c

WORKDIR /work
RUN ln -s build-cov/mjson_fuzz bin-cov && \
    /work/bin-cov || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN clang -g -O0 -pg -fno-omit-frame-pointer -I. \
    -pg -Wl,--allow-multiple-definition \
    -o mjson_fuzz fuzz_harness.c src/mjson.c

WORKDIR /work
RUN ln -s build-uftrace/mjson_fuzz bin-uftrace && \
    /work/bin-uftrace || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
