FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux && \
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
RUN echo "project: csvquote" > /work/proj && \
    echo "version: 0.1.5" >> /work/proj && \
    echo "source: https://github.com/dbro/csvquote/archive/refs/tags/v0.1.5.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/dbro/csvquote/archive/refs/tags/v0.1.5.tar.gz && \
    tar -xzf v0.1.5.tar.gz && \
    rm v0.1.5.tar.gz && \
    cp -a csvquote-0.1.5 build-fuzz && \
    cp -a csvquote-0.1.5 build-cmplog && \
    cp -a csvquote-0.1.5 build-cov && \
    cp -a csvquote-0.1.5 build-uftrace && \
    rm -rf csvquote-0.1.5

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/csvquote bin-fuzz && \
    /work/bin-fuzz --version || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN make CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/csvquote bin-cmplog && \
    /work/bin-cmplog --version || true

# Copy fuzzing resources
COPY csvquote/fuzz/dict /work/dict
COPY csvquote/fuzz/in /work/in
COPY csvquote/fuzz/fuzz.sh /work/fuzz.sh
COPY csvquote/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/csvquote bin-cov && \
    /work/bin-cov --version || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/csvquote bin-uftrace && \
    /work/bin-uftrace --version || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
