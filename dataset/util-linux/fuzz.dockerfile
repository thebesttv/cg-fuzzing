FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake autopoint libtool pkg-config gettext bison flex uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: util-linux" > /work/proj && \
    echo "version: 2.40.2" >> /work/proj && \
    echo "source: https://github.com/util-linux/util-linux/archive/refs/tags/v2.40.2.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/util-linux/util-linux/archive/refs/tags/v2.40.2.tar.gz && \
    tar -xzf v2.40.2.tar.gz && \
    rm v2.40.2.tar.gz && \
    cp -a util-linux-2.40.2 build-fuzz && \
    cp -a util-linux-2.40.2 build-cmplog && \
    cp -a util-linux-2.40.2 build-cov && \
    cp -a util-linux-2.40.2 build-uftrace && \
    rm -rf util-linux-2.40.2

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN ./autogen.sh && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --disable-all-programs \
        --enable-libuuid --enable-uuidgen && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/uuidgen bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN ./autogen.sh && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static --disable-all-programs \
        --enable-libuuid --enable-uuidgen && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/uuidgen bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY util-linux/fuzz/dict /work/dict
COPY util-linux/fuzz/in /work/in
COPY util-linux/fuzz/fuzz.sh /work/fuzz.sh
COPY util-linux/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN ./autogen.sh && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --disable-all-programs \
        --enable-libuuid --enable-uuidgen && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/uuidgen bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN ./autogen.sh && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --prefix=/work/install-uftrace --disable-shared --enable-static --disable-all-programs \
        --enable-libuuid --enable-uuidgen && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/uuidgen bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
