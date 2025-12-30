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
RUN echo "project: datamash" > /work/proj && \
    echo "version: 1.9" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/datamash/datamash-1.9.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/datamash/datamash-1.9.tar.gz && \
    tar -xzf datamash-1.9.tar.gz && \
    rm datamash-1.9.tar.gz && \
    cp -a datamash-1.9 build-fuzz && \
    cp -a datamash-1.9 build-cmplog && \
    cp -a datamash-1.9 build-cov && \
    cp -a datamash-1.9 build-uftrace && \
    rm -rf datamash-1.9

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/datamash bin-fuzz && \
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
RUN ln -s build-cmplog/datamash bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY datamash/fuzz/dict /work/dict
COPY datamash/fuzz/in /work/in
COPY datamash/fuzz/fuzz.sh /work/fuzz.sh
COPY datamash/fuzz/whatsup.sh /work/whatsup.sh
COPY datamash/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY datamash/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY datamash/fuzz/collect-branch.py /work/collect-branch.py
COPY datamash/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY datamash/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/datamash bin-cov && \
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
RUN ln -s install-uftrace/bin/datamash bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
