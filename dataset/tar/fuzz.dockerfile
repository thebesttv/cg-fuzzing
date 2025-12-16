FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget xz-utils uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: tar" > /work/proj && \
    echo "version: 1.35" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/tar/tar-1.35.tar.xz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/tar/tar-1.35.tar.xz && \
    tar -xJf tar-1.35.tar.xz && \
    rm tar-1.35.tar.xz && \
    cp -a tar-1.35 build-fuzz && \
    cp -a tar-1.35 build-cmplog && \
    cp -a tar-1.35 build-cov && \
    cp -a tar-1.35 build-uftrace && \
    rm -rf tar-1.35

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/tar bin-fuzz && \
    /work/bin-fuzz --version | head -2

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/src/tar bin-cmplog && \
    /work/bin-cmplog --version | head -2

# Copy fuzzing resources
COPY tar/fuzz/dict /work/dict
COPY tar/fuzz/in /work/in
COPY tar/fuzz/fuzz.sh /work/fuzz.sh
COPY tar/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/tar bin-cov && \
    /work/bin-cov --version | head -2 && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/tar bin-uftrace && \
    /work/bin-uftrace --version | head -2 && \
    uftrace record /work/bin-uftrace --version | head -2 && \
    uftrace report && \
    rm -rf uftrace.data gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
