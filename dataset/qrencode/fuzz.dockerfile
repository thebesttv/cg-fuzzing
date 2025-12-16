FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool pkg-config uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: qrencode" > /work/proj && \
    echo "version: 4.1.1" >> /work/proj && \
    echo "source: https://github.com/fukuchi/libqrencode/archive/refs/tags/v4.1.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/fukuchi/libqrencode/archive/refs/tags/v4.1.1.tar.gz && \
    tar -xzf v4.1.1.tar.gz && \
    rm v4.1.1.tar.gz && \
    cp -a libqrencode-4.1.1 build-fuzz && \
    cp -a libqrencode-4.1.1 build-cmplog && \
    cp -a libqrencode-4.1.1 build-cov && \
    cp -a libqrencode-4.1.1 build-uftrace && \
    rm -rf libqrencode-4.1.1

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN autoreconf -i && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --with-tools --without-png && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/qrencode bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN autoreconf -i && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static --with-tools --without-png && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/qrencode bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY qrencode/fuzz/dict /work/dict
COPY qrencode/fuzz/in /work/in
COPY qrencode/fuzz/fuzz.sh /work/fuzz.sh
COPY qrencode/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN autoreconf -i && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --with-tools --without-png && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/qrencode bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN autoreconf -i && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --with-tools --without-png && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/qrencode bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
