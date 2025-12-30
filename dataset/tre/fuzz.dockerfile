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
RUN echo "project: tre" > /work/proj && \
    echo "version: 0.9.0" >> /work/proj && \
    echo "source: https://github.com/laurikari/tre/releases/download/v0.9.0/tre-0.9.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/laurikari/tre/releases/download/v0.9.0/tre-0.9.0.tar.gz && \
    tar -xzf tre-0.9.0.tar.gz && \
    rm tre-0.9.0.tar.gz && \
    cp -a tre-0.9.0 build-fuzz && \
    cp -a tre-0.9.0 build-cmplog && \
    cp -a tre-0.9.0 build-cov && \
    cp -a tre-0.9.0 build-uftrace && \
    rm -rf tre-0.9.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/agrep bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/src/agrep bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY tre/fuzz/dict /work/dict
COPY tre/fuzz/in /work/in
COPY tre/fuzz/fuzz.sh /work/fuzz.sh
COPY tre/fuzz/whatsup.sh /work/whatsup.sh
COPY tre/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY tre/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY tre/fuzz/collect-branch.py /work/collect-branch.py
COPY tre/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY tre/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/agrep bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/agrep bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
