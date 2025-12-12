FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
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
RUN echo "project: gdbm" > /work/proj && \
    echo "version: 1.26" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/gdbm/gdbm-1.26.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/gdbm/gdbm-1.26.tar.gz && \
    tar -xzf gdbm-1.26.tar.gz && \
    rm gdbm-1.26.tar.gz && \
    cp -a gdbm-1.26 build-fuzz && \
    cp -a gdbm-1.26 build-cmplog && \
    cp -a gdbm-1.26 build-cov && \
    cp -a gdbm-1.26 build-uftrace && \
    rm -rf gdbm-1.26

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --without-readline && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/tools/gdbm_load bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static --without-readline && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/tools/gdbm_load bin-cmplog

# Copy fuzzing resources
COPY gdbm/fuzz/dict /work/dict
COPY gdbm/fuzz/in /work/in
COPY gdbm/fuzz/fuzz.sh /work/fuzz.sh
COPY gdbm/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --without-readline && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/tools/gdbm_load bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --without-readline --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/gdbm_load bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
