FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: zstd" > /work/proj && \
    echo "version: 1.5.7" >> /work/proj && \
    echo "source: https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz && \
    tar -xzf zstd-1.5.7.tar.gz && \
    rm zstd-1.5.7.tar.gz && \
    cp -a zstd-1.5.7 build-fuzz && \
    cp -a zstd-1.5.7 build-cmplog && \
    cp -a zstd-1.5.7 build-cov && \
    cp -a zstd-1.5.7 build-uftrace && \
    rm -rf zstd-1.5.7

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make -j$(nproc) zstd-release

WORKDIR /work
RUN ln -s build-fuzz/programs/zstd bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make -j$(nproc) zstd-release

WORKDIR /work
RUN ln -s build-cmplog/programs/zstd bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY zstd/fuzz/dict /work/dict
COPY zstd/fuzz/in /work/in
COPY zstd/fuzz/fuzz.sh /work/fuzz.sh
COPY zstd/fuzz/whatsup.sh /work/whatsup.sh
COPY zstd/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY zstd/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY zstd/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    make -j$(nproc) zstd-release

WORKDIR /work
RUN ln -s build-cov/programs/zstd bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    make -j$(nproc) zstd-release

WORKDIR /work
RUN ln -s build-uftrace/programs/zstd bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
