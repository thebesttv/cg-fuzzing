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
RUN echo "project: zlib" > /work/proj && \
    echo "version: 1.3.1" >> /work/proj && \
    echo "source: https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz && \
    tar -xzf zlib-1.3.1.tar.gz && \
    rm zlib-1.3.1.tar.gz && \
    cp -a zlib-1.3.1 build-fuzz && \
    cp -a zlib-1.3.1 build-cmplog && \
    cp -a zlib-1.3.1 build-cov && \
    cp -a zlib-1.3.1 build-uftrace && \
    rm -rf zlib-1.3.1

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --static && \
    make -j$(nproc) && \
    make -j$(nproc) minigzip

WORKDIR /work
RUN ln -s build-fuzz/minigzip bin-fuzz && \
    file /work/bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --static && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) minigzip

WORKDIR /work
RUN ln -s build-cmplog/minigzip bin-cmplog && \
    file /work/bin-cmplog

# Copy fuzzing resources
COPY zlib/fuzz/dict /work/dict
COPY zlib/fuzz/in /work/in
COPY zlib/fuzz/fuzz.sh /work/fuzz.sh
COPY zlib/fuzz/whatsup.sh /work/whatsup.sh
COPY zlib/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY zlib/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY zlib/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --static && \
    make -j$(nproc) && \
    make -j$(nproc) minigzip

WORKDIR /work
RUN ln -s build-cov/minigzip bin-cov && \
    file /work/bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --static --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make -j$(nproc) minigzip && \
    make install

WORKDIR /work
RUN ln -s build-uftrace/minigzip bin-uftrace && \
    file /work/bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
