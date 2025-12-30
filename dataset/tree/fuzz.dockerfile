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
RUN echo "project: tree" > /work/proj && \
    echo "version: 2.1.3" >> /work/proj && \
    echo "source: https://github.com/Old-Man-Programmer/tree/archive/refs/tags/2.1.3.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/Old-Man-Programmer/tree/archive/refs/tags/2.1.3.tar.gz && \
    tar -xzf 2.1.3.tar.gz && \
    rm 2.1.3.tar.gz && \
    cp -a tree-2.1.3 build-fuzz && \
    cp -a tree-2.1.3 build-cmplog && \
    cp -a tree-2.1.3 build-cov && \
    cp -a tree-2.1.3 build-uftrace && \
    rm -rf tree-2.1.3

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make CC=afl-clang-lto LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/tree bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN make CC=afl-clang-lto LDFLAGS="-static -Wl,--allow-multiple-definition" AFL_LLVM_CMPLOG=1 -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/tree bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY tree/fuzz/dict /work/dict
COPY tree/fuzz/in /work/in
COPY tree/fuzz/fuzz.sh /work/fuzz.sh
COPY tree/fuzz/whatsup.sh /work/whatsup.sh
COPY tree/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY tree/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY tree/fuzz/collect-branch.py /work/collect-branch.py
COPY tree/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make CC=clang CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/tree bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make CC=clang CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" LDFLAGS="-pg -Wl,--allow-multiple-definition" -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/tree bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
