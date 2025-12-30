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
RUN echo "project: aha" > /work/proj && \
    echo "version: 0.5.1" >> /work/proj && \
    echo "source: https://github.com/theZiz/aha/archive/refs/tags/0.5.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/theZiz/aha/archive/refs/tags/0.5.1.tar.gz && \
    tar -xzf 0.5.1.tar.gz && \
    rm 0.5.1.tar.gz && \
    cp -a aha-0.5.1 build-fuzz && \
    cp -a aha-0.5.1 build-cmplog && \
    cp -a aha-0.5.1 build-cov && \
    cp -a aha-0.5.1 build-uftrace && \
    rm -rf aha-0.5.1

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/aha bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/aha bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY aha/fuzz/dict /work/dict
COPY aha/fuzz/in /work/in
COPY aha/fuzz/fuzz.sh /work/fuzz.sh
COPY aha/fuzz/whatsup.sh /work/whatsup.sh
COPY aha/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY aha/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY aha/fuzz/collect-branch.py /work/collect-branch.py
COPY aha/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY aha/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/aha bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/aha bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
