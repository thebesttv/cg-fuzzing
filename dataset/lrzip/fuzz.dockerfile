FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool libbz2-dev liblzo2-dev zlib1g-dev liblz4-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: lrzip" > /work/proj && \
    echo "version: 0.651" >> /work/proj && \
    echo "source: https://github.com/ckolivas/lrzip/archive/refs/tags/v0.651.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/ckolivas/lrzip/archive/refs/tags/v0.651.tar.gz && \
    tar -xzf v0.651.tar.gz && \
    rm v0.651.tar.gz && \
    cp -a lrzip-0.651 build-fuzz && \
    cp -a lrzip-0.651 build-cmplog && \
    cp -a lrzip-0.651 build-cov && \
    cp -a lrzip-0.651 build-uftrace && \
    rm -rf lrzip-0.651

# Build fuzz binary with afl-clang-fast
WORKDIR /work/build-fuzz
RUN ./autogen.sh && \
    CC=afl-clang-fast \
    CXX=afl-clang-fast++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/lrzip bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-fast + CMPLOG
WORKDIR /work/build-cmplog
RUN ./autogen.sh && \
    CC=afl-clang-fast \
    CXX=afl-clang-fast++ \
    AFL_LLVM_CMPLOG=1 \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/lrzip bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY lrzip/fuzz/dict /work/dict
COPY lrzip/fuzz/in /work/in
COPY lrzip/fuzz/fuzz.sh /work/fuzz.sh
COPY lrzip/fuzz/whatsup.sh /work/whatsup.sh
COPY lrzip/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN ./autogen.sh && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/lrzip bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN ./autogen.sh && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/lrzip bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
