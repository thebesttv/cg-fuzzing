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
RUN echo "project: zopfli" > /work/proj && \
    echo "version: 1.0.3" >> /work/proj && \
    echo "source: https://github.com/google/zopfli/archive/refs/tags/zopfli-1.0.3.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/google/zopfli/archive/refs/tags/zopfli-1.0.3.tar.gz && \
    tar -xzf zopfli-1.0.3.tar.gz && \
    rm zopfli-1.0.3.tar.gz && \
    cp -a zopfli-zopfli-1.0.3 build-fuzz && \
    cp -a zopfli-zopfli-1.0.3 build-cmplog && \
    cp -a zopfli-zopfli-1.0.3 build-cov && \
    cp -a zopfli-zopfli-1.0.3 build-uftrace && \
    rm -rf zopfli-zopfli-1.0.3

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make CC=afl-clang-lto \
    CFLAGS="-O2 -W -Wall -Wextra -ansi -pedantic -lm -Wno-unused-function" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    zopfli

WORKDIR /work
RUN ln -s build-fuzz/zopfli bin-fuzz && \
    /work/bin-fuzz -h || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    CFLAGS="-O2 -W -Wall -Wextra -ansi -pedantic -lm -Wno-unused-function" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    zopfli

WORKDIR /work
RUN ln -s build-cmplog/zopfli bin-cmplog && \
    /work/bin-cmplog -h || true

# Copy fuzzing resources
COPY zopfli/fuzz/dict /work/dict
COPY zopfli/fuzz/in /work/in
COPY zopfli/fuzz/fuzz.sh /work/fuzz.sh
COPY zopfli/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping -W -Wall -Wextra -ansi -pedantic -lm -Wno-unused-function" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    zopfli

WORKDIR /work
RUN ln -s build-cov/zopfli bin-cov && \
    /work/bin-cov -h || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer -W -Wall -Wextra -ansi -pedantic -lm -Wno-unused-function" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    zopfli

WORKDIR /work
RUN ln -s build-uftrace/zopfli bin-uftrace && \
    /work/bin-uftrace -h || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
