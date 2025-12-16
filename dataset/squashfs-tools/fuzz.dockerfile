FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget zlib1g-dev liblzo2-dev liblz4-dev libzstd-dev liblzma-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: squashfs-tools" > /work/proj && \
    echo "version: 4.7.4" >> /work/proj && \
    echo "source: https://github.com/plougher/squashfs-tools/releases/download/4.7.4/squashfs-tools-4.7.4.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/plougher/squashfs-tools/releases/download/4.7.4/squashfs-tools-4.7.4.tar.gz && \
    tar -xzf squashfs-tools-4.7.4.tar.gz && \
    rm squashfs-tools-4.7.4.tar.gz && \
    cp -a squashfs-tools-4.7.4 build-fuzz && \
    cp -a squashfs-tools-4.7.4 build-cmplog && \
    cp -a squashfs-tools-4.7.4 build-cov && \
    cp -a squashfs-tools-4.7.4 build-uftrace && \
    rm -rf squashfs-tools-4.7.4

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz/squashfs-tools
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make -j$(nproc) unsquashfs

WORKDIR /work
RUN ln -s build-fuzz/squashfs-tools/unsquashfs bin-fuzz && \
    /work/bin-fuzz -v || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog/squashfs-tools
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make -j$(nproc) unsquashfs

WORKDIR /work
RUN ln -s build-cmplog/squashfs-tools/unsquashfs bin-cmplog && \
    /work/bin-cmplog -v || true

# Copy fuzzing resources
COPY squashfs-tools/fuzz/dict /work/dict
COPY squashfs-tools/fuzz/in /work/in
COPY squashfs-tools/fuzz/fuzz.sh /work/fuzz.sh
COPY squashfs-tools/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov/squashfs-tools
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    make -j$(nproc) unsquashfs

WORKDIR /work
RUN ln -s build-cov/squashfs-tools/unsquashfs bin-cov && \
    /work/bin-cov -v || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace/squashfs-tools
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    make -j$(nproc) unsquashfs

WORKDIR /work
RUN ln -s build-uftrace/squashfs-tools/unsquashfs bin-uftrace && \
    /work/bin-uftrace -v || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
