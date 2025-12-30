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
RUN echo "project: tinycbor" > /work/proj && \
    echo "version: 0.6.1" >> /work/proj && \
    echo "source: https://github.com/intel/tinycbor/archive/refs/tags/v0.6.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/intel/tinycbor/archive/refs/tags/v0.6.1.tar.gz && \
    tar -xzf v0.6.1.tar.gz && \
    rm v0.6.1.tar.gz && \
    cp -a tinycbor-0.6.1 build-fuzz && \
    cp -a tinycbor-0.6.1 build-cmplog && \
    cp -a tinycbor-0.6.1 build-cov && \
    cp -a tinycbor-0.6.1 build-uftrace && \
    rm -rf tinycbor-0.6.1

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make clean || true && \
    make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    BUILD_SHARED=0 \
    BUILD_STATIC=1

WORKDIR /work
RUN ln -s build-fuzz/bin/cbordump bin-fuzz && \
    /work/bin-fuzz -h | head -3

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN make clean || true && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    BUILD_SHARED=0 \
    BUILD_STATIC=1

WORKDIR /work
RUN ln -s build-cmplog/bin/cbordump bin-cmplog && \
    /work/bin-cmplog -h | head -3

# Copy fuzzing resources
COPY tinycbor/fuzz/dict /work/dict
COPY tinycbor/fuzz/in /work/in
COPY tinycbor/fuzz/fuzz.sh /work/fuzz.sh
COPY tinycbor/fuzz/whatsup.sh /work/whatsup.sh
COPY tinycbor/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY tinycbor/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY tinycbor/fuzz/collect-branch.py /work/collect-branch.py
COPY tinycbor/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make clean || true && \
    make -j$(nproc) \
    CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    BUILD_SHARED=0 \
    BUILD_STATIC=1

WORKDIR /work
RUN ln -s build-cov/bin/cbordump bin-cov && \
    /work/bin-cov -h | head -3 && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make clean || true && \
    make -j$(nproc) \
    CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    BUILD_SHARED=0 \
    BUILD_STATIC=1

WORKDIR /work
RUN ln -s build-uftrace/bin/cbordump bin-uftrace && \
    /work/bin-uftrace -h | head -3 && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
