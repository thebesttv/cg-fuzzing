FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: daemonize" > /work/proj && \
    echo "version: 1.7.8" >> /work/proj && \
    echo "source: https://github.com/bmc/daemonize/archive/refs/tags/release-1.7.8.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/bmc/daemonize/archive/refs/tags/release-1.7.8.tar.gz && \
    tar -xzf release-1.7.8.tar.gz && \
    rm release-1.7.8.tar.gz && \
    cp -a daemonize-release-1.7.8 build-fuzz && \
    cp -a daemonize-release-1.7.8 build-cmplog && \
    cp -a daemonize-release-1.7.8 build-cov && \
    cp -a daemonize-release-1.7.8 build-uftrace && \
    rm -rf daemonize-release-1.7.8

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/daemonize bin-fuzz && \
    /work/bin-fuzz --help || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/daemonize bin-cmplog && \
    /work/bin-cmplog --help || true

# Copy fuzzing resources
COPY daemonize/fuzz/dict /work/dict
COPY daemonize/fuzz/in /work/in
COPY daemonize/fuzz/fuzz.sh /work/fuzz.sh
COPY daemonize/fuzz/whatsup.sh /work/whatsup.sh
COPY daemonize/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY daemonize/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY daemonize/fuzz/collect-branch.py /work/collect-branch.py
COPY daemonize/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY daemonize/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/daemonize bin-cov && \
    /work/bin-cov --help || true && \
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
RUN ln -s install-uftrace/sbin/daemonize bin-uftrace && \
    /work/bin-uftrace --help || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
