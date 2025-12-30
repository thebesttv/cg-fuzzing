FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: xdelta" > /work/proj && \
    echo "version: 3.1.0" >> /work/proj && \
    echo "source: https://github.com/jmacd/xdelta/archive/refs/tags/v3.1.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/jmacd/xdelta/archive/refs/tags/v3.1.0.tar.gz && \
    tar -xzf v3.1.0.tar.gz && \
    rm v3.1.0.tar.gz && \
    cp -a xdelta-3.1.0 build-fuzz && \
    cp -a xdelta-3.1.0 build-cmplog && \
    cp -a xdelta-3.1.0 build-cov && \
    cp -a xdelta-3.1.0 build-uftrace && \
    rm -rf xdelta-3.1.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz/xdelta3
RUN autoreconf -fi && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/xdelta3/xdelta3 bin-fuzz && \
    /work/bin-fuzz -V || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog/xdelta3
RUN autoreconf -fi && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/xdelta3/xdelta3 bin-cmplog && \
    /work/bin-cmplog -V || true

# Copy fuzzing resources
COPY xdelta/fuzz/dict /work/dict
COPY xdelta/fuzz/in /work/in
COPY xdelta/fuzz/fuzz.sh /work/fuzz.sh
COPY xdelta/fuzz/whatsup.sh /work/whatsup.sh
COPY xdelta/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY xdelta/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY xdelta/fuzz/collect-branch.py /work/collect-branch.py
COPY xdelta/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY xdelta/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov/xdelta3
RUN autoreconf -fi && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/xdelta3/xdelta3 bin-cov && \
    /work/bin-cov -V || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace/xdelta3
RUN autoreconf -fi && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/xdelta3/xdelta3 bin-uftrace && \
    /work/bin-uftrace -V || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
