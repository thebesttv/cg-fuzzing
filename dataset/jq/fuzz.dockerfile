FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool bison flex uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: jq" > /work/proj && \
    echo "version: 1.8.1" >> /work/proj && \
    echo "source: https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-1.8.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-1.8.1.tar.gz && \
    tar -xzf jq-1.8.1.tar.gz && \
    rm jq-1.8.1.tar.gz && \
    cp -r jq-1.8.1 build-fuzz && \
    cp -r jq-1.8.1 build-cmplog && \
    cp -r jq-1.8.1 build-cov && \
    cp -r jq-1.8.1 build-uftrace && \
    rm -rf jq-1.8.1

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --with-oniguruma=builtin --disable-shared --enable-all-static && \
    make -j$(nproc) && \
    cp jq /work/jq-fuzz

WORKDIR /work
RUN ln -s jq-fuzz bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --with-oniguruma=builtin --disable-shared --enable-all-static && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) && \
    cp jq /work/jq-cmplog

WORKDIR /work
RUN ln -s jq-cmplog bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY jq/fuzz/dict /work/dict
COPY jq/fuzz/in /work/in
COPY jq/fuzz/fuzz.sh /work/fuzz.sh
COPY jq/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --with-oniguruma=builtin --disable-shared --enable-all-static && \
    make -j$(nproc) && \
    cp jq /work/jq-cov

WORKDIR /work
RUN ln -s jq-cov bin-cov && \
    /work/bin-cov --version && \
    rm -rf /work/build-cov

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --with-oniguruma=builtin --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install && \
    cp /work/install-uftrace/bin/jq /work/jq-uftrace

WORKDIR /work
RUN ln -s jq-uftrace bin-uftrace && \
    /work/bin-uftrace --version && \
    uftrace record /work/bin-uftrace --version && \
    uftrace report && \
    rm -rf uftrace.data /work/build-uftrace

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
