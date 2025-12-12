FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libreadline-dev libncurses-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: calc" > /work/proj && \
    echo "version: 2.15.1.1" >> /work/proj && \
    echo "source: https://github.com/lcn2/calc/releases/download/v2.15.1.1/calc-2.15.1.1.tar.bz2" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/lcn2/calc/releases/download/v2.15.1.1/calc-2.15.1.1.tar.bz2 && \
    tar -xjf calc-2.15.1.1.tar.bz2 && \
    rm calc-2.15.1.1.tar.bz2 && \
    cp -a calc-2.15.1.1 build-fuzz && \
    cp -a calc-2.15.1.1 build-cmplog && \
    cp -a calc-2.15.1.1 build-cov && \
    cp -a calc-2.15.1.1 build-uftrace && \
    rm -rf calc-2.15.1.1

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    make calc-static-only BLD_TYPE=calc-static-only -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/calc-static bin-fuzz && \
    /work/bin-fuzz help version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make calc-static-only BLD_TYPE=calc-static-only -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/calc-static bin-cmplog && \
    /work/bin-cmplog help version

# Copy fuzzing resources
COPY calc/fuzz/dict /work/dict
COPY calc/fuzz/in /work/in
COPY calc/fuzz/fuzz.sh /work/fuzz.sh
COPY calc/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -Wl,--allow-multiple-definition" \
    make calc-static-only BLD_TYPE=calc-static-only -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/calc-static bin-cov && \
    /work/bin-cov help version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    make calc-static-only BLD_TYPE=calc-static-only -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/calc-static bin-uftrace && \
    /work/bin-uftrace help version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
