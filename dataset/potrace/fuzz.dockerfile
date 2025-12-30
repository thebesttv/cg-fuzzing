FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget zlib1g-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: potrace" > /work/proj && \
    echo "version: 1.16" >> /work/proj && \
    echo "source: https://potrace.sourceforge.net/download/1.16/potrace-1.16.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://potrace.sourceforge.net/download/1.16/potrace-1.16.tar.gz && \
    tar -xzf potrace-1.16.tar.gz && \
    rm potrace-1.16.tar.gz && \
    cp -a potrace-1.16 build-fuzz && \
    cp -a potrace-1.16 build-cmplog && \
    cp -a potrace-1.16 build-cov && \
    cp -a potrace-1.16 build-uftrace && \
    rm -rf potrace-1.16

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/potrace bin-fuzz && \
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
RUN ln -s build-cmplog/src/potrace bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY potrace/fuzz/dict /work/dict
COPY potrace/fuzz/in /work/in
COPY potrace/fuzz/fuzz.sh /work/fuzz.sh
COPY potrace/fuzz/whatsup.sh /work/whatsup.sh
COPY potrace/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY potrace/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY potrace/fuzz/collect-branch.py /work/collect-branch.py
COPY potrace/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY potrace/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/potrace bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/src/potrace bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
