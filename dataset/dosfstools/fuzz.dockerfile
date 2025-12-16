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
RUN echo "project: dosfstools" > /work/proj && \
    echo "version: 4.2" >> /work/proj && \
    echo "source: https://github.com/dosfstools/dosfstools/releases/download/v4.2/dosfstools-4.2.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/dosfstools/dosfstools/releases/download/v4.2/dosfstools-4.2.tar.gz && \
    tar -xzf dosfstools-4.2.tar.gz && \
    rm dosfstools-4.2.tar.gz && \
    cp -a dosfstools-4.2 build-fuzz && \
    cp -a dosfstools-4.2 build-cmplog && \
    cp -a dosfstools-4.2 build-cov && \
    cp -a dosfstools-4.2 build-uftrace && \
    rm -rf dosfstools-4.2

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/fsck.fat bin-fuzz && \
    /work/bin-fuzz --help || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/src/fsck.fat bin-cmplog && \
    /work/bin-cmplog --help || true

# Copy fuzzing resources
COPY dosfstools/fuzz/dict /work/dict
COPY dosfstools/fuzz/in /work/in
COPY dosfstools/fuzz/fuzz.sh /work/fuzz.sh
COPY dosfstools/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/fsck.fat bin-cov && \
    /work/bin-cov --help || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/src/fsck.fat bin-uftrace && \
    /work/bin-uftrace --help || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
