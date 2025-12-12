FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget uftrace ghostscript fonts-urw-base35 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: antiword" > /work/proj && \
    echo "version: main" >> /work/proj && \
    echo "source: https://github.com/grobian/antiword/archive/refs/heads/main.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/grobian/antiword/archive/refs/heads/main.tar.gz -O antiword.tar.gz && \
    tar -xzf antiword.tar.gz && \
    rm antiword.tar.gz && \
    cp -a antiword-main build-fuzz && \
    cp -a antiword-main build-cmplog && \
    cp -a antiword-main build-cov && \
    cp -a antiword-main build-uftrace && \
    rm -rf antiword-main

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make CC=afl-clang-lto \
    LD=afl-clang-lto \
    CFLAGS="-O2 -DNDEBUG" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/antiword bin-fuzz && \
    /work/bin-fuzz || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    LD=afl-clang-lto \
    CFLAGS="-O2 -DNDEBUG" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/antiword bin-cmplog && \
    /work/bin-cmplog || true

# Copy fuzzing resources
COPY antiword/fuzz/dict /work/dict
COPY antiword/fuzz/in /work/in
COPY antiword/fuzz/fuzz.sh /work/fuzz.sh
COPY antiword/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make CC=clang \
    LD=clang \
    CFLAGS="-g -O0 -DNDEBUG -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/antiword bin-cov && \
    /work/bin-cov || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make CC=clang \
    LD=clang \
    CFLAGS="-g -O0 -DNDEBUG -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/antiword bin-uftrace && \
    /work/bin-uftrace || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
