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
RUN echo "project: bchunk" > /work/proj && \
    echo "version: 1.2.2" >> /work/proj && \
    echo "source: http://he.fi/bchunk/bchunk-1.2.2.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 http://he.fi/bchunk/bchunk-1.2.2.tar.gz && \
    tar -xzf bchunk-1.2.2.tar.gz && \
    rm bchunk-1.2.2.tar.gz && \
    cp -a bchunk-1.2.2 build-fuzz && \
    cp -a bchunk-1.2.2 build-cmplog && \
    cp -a bchunk-1.2.2 build-cov && \
    cp -a bchunk-1.2.2 build-uftrace && \
    rm -rf bchunk-1.2.2

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make CC=afl-clang-lto LD=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/bchunk bin-fuzz && \
    echo "bchunk version:" && /work/bin-fuzz 2>&1 | head -5 || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto LD=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/bchunk bin-cmplog && \
    echo "bchunk cmplog version:" && /work/bin-cmplog 2>&1 | head -5 || true

# Copy fuzzing resources
COPY bchunk/fuzz/dict /work/dict
COPY bchunk/fuzz/in /work/in
COPY bchunk/fuzz/fuzz.sh /work/fuzz.sh
COPY bchunk/fuzz/whatsup.sh /work/whatsup.sh
COPY bchunk/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make CC=clang LD=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/bchunk bin-cov && \
    echo "bchunk cov version:" && /work/bin-cov 2>&1 | head -5 || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make CC=clang LD=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/bchunk bin-uftrace && \
    echo "bchunk uftrace version:" && /work/bin-uftrace 2>&1 | head -5 || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
