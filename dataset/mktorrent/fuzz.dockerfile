FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libssl-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: mktorrent" > /work/proj && \
    echo "version: 1.1" >> /work/proj && \
    echo "source: https://github.com/pobrn/mktorrent/archive/refs/tags/v1.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/pobrn/mktorrent/archive/refs/tags/v1.1.tar.gz && \
    tar -xzf v1.1.tar.gz && \
    rm v1.1.tar.gz && \
    cp -a mktorrent-1.1 build-fuzz && \
    cp -a mktorrent-1.1 build-cmplog && \
    cp -a mktorrent-1.1 build-cov && \
    cp -a mktorrent-1.1 build-uftrace && \
    rm -rf mktorrent-1.1

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    USE_OPENSSL=1 \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/mktorrent bin-fuzz && \
    /work/bin-fuzz -h 2>&1 | head -1

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    USE_OPENSSL=1 \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/mktorrent bin-cmplog && \
    /work/bin-cmplog -h 2>&1 | head -1

# Copy fuzzing resources
COPY mktorrent/fuzz/dict /work/dict
COPY mktorrent/fuzz/in /work/in
COPY mktorrent/fuzz/fuzz.sh /work/fuzz.sh
COPY mktorrent/fuzz/whatsup.sh /work/whatsup.sh
COPY mktorrent/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    USE_OPENSSL=1 \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/mktorrent bin-cov && \
    /work/bin-cov -h 2>&1 | head -1 && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    USE_OPENSSL=1 \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/mktorrent bin-uftrace && \
    /work/bin-uftrace -h 2>&1 | head -1 && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
