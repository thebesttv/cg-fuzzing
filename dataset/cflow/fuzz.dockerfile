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
RUN echo "project: cflow" > /work/proj && \
    echo "version: 1.7" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/cflow/cflow-1.7.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/cflow/cflow-1.7.tar.gz && \
    tar -xzf cflow-1.7.tar.gz && \
    rm cflow-1.7.tar.gz && \
    cp -a cflow-1.7 build-fuzz && \
    cp -a cflow-1.7 build-cmplog && \
    cp -a cflow-1.7 build-cov && \
    cp -a cflow-1.7 build-uftrace && \
    rm -rf cflow-1.7

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-nls && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/cflow bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-nls && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/src/cflow bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY cflow/fuzz/dict /work/dict
COPY cflow/fuzz/in /work/in
COPY cflow/fuzz/fuzz.sh /work/fuzz.sh
COPY cflow/fuzz/whatsup.sh /work/whatsup.sh
COPY cflow/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY cflow/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY cflow/fuzz/collect-branch.py /work/collect-branch.py
COPY cflow/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY cflow/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-nls && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/cflow bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-nls && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/src/cflow bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
