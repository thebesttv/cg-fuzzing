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
RUN echo "project: lz4" > /work/proj && \
    echo "version: 1.10.0" >> /work/proj && \
    echo "source: https://github.com/lz4/lz4/releases/download/v1.10.0/lz4-1.10.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/lz4/lz4/releases/download/v1.10.0/lz4-1.10.0.tar.gz && \
    tar -xzf lz4-1.10.0.tar.gz && \
    rm lz4-1.10.0.tar.gz && \
    cp -a lz4-1.10.0 build-fuzz && \
    cp -a lz4-1.10.0 build-cmplog && \
    cp -a lz4-1.10.0 build-cov && \
    cp -a lz4-1.10.0 build-uftrace && \
    rm -rf lz4-1.10.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make clean || true && \
    make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    lz4

WORKDIR /work
RUN ln -s build-fuzz/lz4 bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN make clean || true && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    lz4

WORKDIR /work
RUN ln -s build-cmplog/lz4 bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY lz4/fuzz/dict /work/dict
COPY lz4/fuzz/in /work/in
COPY lz4/fuzz/fuzz.sh /work/fuzz.sh
COPY lz4/fuzz/whatsup.sh /work/whatsup.sh
COPY lz4/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY lz4/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY lz4/fuzz/collect-branch.py /work/collect-branch.py
COPY lz4/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY lz4/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make clean || true && \
    make -j$(nproc) \
    CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    lz4

WORKDIR /work
RUN ln -s build-cov/lz4 bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make clean || true && \
    make -j$(nproc) \
    CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    PREFIX=/work/install-uftrace \
    lz4 && \
    mkdir -p /work/install-uftrace/bin && \
    cp lz4 /work/install-uftrace/bin/

WORKDIR /work
RUN ln -s install-uftrace/bin/lz4 bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
