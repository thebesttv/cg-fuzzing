FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool pkg-config zlib1g-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: libhtp" > /work/proj && \
    echo "version: 0.5.52" >> /work/proj && \
    echo "source: https://github.com/OISF/libhtp/archive/refs/tags/0.5.52.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/OISF/libhtp/archive/refs/tags/0.5.52.tar.gz && \
    tar -xzf 0.5.52.tar.gz && \
    rm 0.5.52.tar.gz && \
    cp -a libhtp-0.5.52 build-fuzz && \
    cp -a libhtp-0.5.52 build-cmplog && \
    cp -a libhtp-0.5.52 build-cov && \
    cp -a libhtp-0.5.52 build-uftrace && \
    rm -rf libhtp-0.5.52

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN ./autogen.sh && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc) && \
    cd test && make test_fuzz

WORKDIR /work
RUN ln -s build-fuzz/test/test_fuzz bin-fuzz && \
    /work/bin-fuzz 2>&1 | head -1

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN ./autogen.sh && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) && \
    cd test && AFL_LLVM_CMPLOG=1 make test_fuzz

WORKDIR /work
RUN ln -s build-cmplog/test/test_fuzz bin-cmplog && \
    /work/bin-cmplog 2>&1 | head -1

# Copy fuzzing resources
COPY libhtp/fuzz/dict /work/dict
COPY libhtp/fuzz/in /work/in
COPY libhtp/fuzz/fuzz.sh /work/fuzz.sh
COPY libhtp/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN ./autogen.sh && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc) && \
    cd test && make test_fuzz

WORKDIR /work
RUN ln -s build-cov/test/test_fuzz bin-cov && \
    /work/bin-cov 2>&1 | head -1 && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN ./autogen.sh && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install && \
    cd test && make test_fuzz && \
    mkdir -p /work/install-uftrace/bin && \
    cp test_fuzz /work/install-uftrace/bin/

WORKDIR /work
RUN ln -s install-uftrace/bin/test_fuzz bin-uftrace && \
    /work/bin-uftrace 2>&1 | head -1 && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
