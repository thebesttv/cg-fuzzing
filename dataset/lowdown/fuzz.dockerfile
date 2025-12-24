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
RUN echo "project: lowdown" > /work/proj && \
    echo "version: 1.1.0" >> /work/proj && \
    echo "source: https://github.com/kristapsdz/lowdown/archive/refs/tags/VERSION_1_1_0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/kristapsdz/lowdown/archive/refs/tags/VERSION_1_1_0.tar.gz && \
    tar -xzf VERSION_1_1_0.tar.gz && \
    rm VERSION_1_1_0.tar.gz && \
    cp -a lowdown-VERSION_1_1_0 build-fuzz && \
    cp -a lowdown-VERSION_1_1_0 build-cmplog && \
    cp -a lowdown-VERSION_1_1_0 build-cov && \
    cp -a lowdown-VERSION_1_1_0 build-uftrace && \
    rm -rf lowdown-VERSION_1_1_0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN ./configure && \
    make lowdown CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/lowdown bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN ./configure && \
    AFL_LLVM_CMPLOG=1 make lowdown CC=afl-clang-lto CFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/lowdown bin-cmplog

# Copy fuzzing resources
COPY lowdown/fuzz/dict /work/dict
COPY lowdown/fuzz/in /work/in
COPY lowdown/fuzz/fuzz.sh /work/fuzz.sh
COPY lowdown/fuzz/whatsup.sh /work/whatsup.sh
COPY lowdown/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY lowdown/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY lowdown/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN ./configure && \
    make lowdown CC=clang CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/lowdown bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN ./configure && \
    make lowdown CC=clang CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" LDFLAGS="-pg -Wl,--allow-multiple-definition" -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/lowdown bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
