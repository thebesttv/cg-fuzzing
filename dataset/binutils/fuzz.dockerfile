FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget texinfo zlib1g-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: binutils" > /work/proj && \
    echo "version: 2.43.1" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/binutils/binutils-2.43.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/binutils/binutils-2.43.1.tar.gz && \
    tar -xzf binutils-2.43.1.tar.gz && \
    rm binutils-2.43.1.tar.gz && \
    cp -a binutils-2.43.1 build-fuzz && \
    cp -a binutils-2.43.1 build-cmplog && \
    cp -a binutils-2.43.1 build-cov && \
    cp -a binutils-2.43.1 build-uftrace && \
    rm -rf binutils-2.43.1

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure \
        --disable-shared \
        --enable-static \
        --disable-werror \
        --disable-gdb \
        --disable-libdecnumber \
        --disable-readline \
        --disable-sim && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/binutils/readelf bin-fuzz && \
    /work/bin-fuzz --version | head -3

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure \
        --disable-shared \
        --enable-static \
        --disable-werror \
        --disable-gdb \
        --disable-libdecnumber \
        --disable-readline \
        --disable-sim && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/binutils/readelf bin-cmplog && \
    /work/bin-cmplog --version | head -3

# Copy fuzzing resources
COPY binutils/fuzz/dict /work/dict
COPY binutils/fuzz/in /work/in
COPY binutils/fuzz/fuzz.sh /work/fuzz.sh
COPY binutils/fuzz/whatsup.sh /work/whatsup.sh
COPY binutils/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY binutils/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY binutils/fuzz/collect-branch.py /work/collect-branch.py
COPY binutils/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure \
        --disable-shared \
        --enable-static \
        --disable-werror \
        --disable-gdb \
        --disable-libdecnumber \
        --disable-readline \
        --disable-sim && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/binutils/readelf bin-cov && \
    /work/bin-cov --version | head -3 && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure \
        --disable-shared \
        --enable-static \
        --disable-werror \
        --disable-gdb \
        --disable-libdecnumber \
        --disable-readline \
        --disable-sim \
        --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/readelf bin-uftrace && \
    /work/bin-uftrace --version | head -3 && \
    uftrace record /work/bin-uftrace --version && \
    uftrace report && \
    rm -rf uftrace.data gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
