FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libssl-dev zlib1g-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: curl" > /work/proj && \
    echo "version: 8.17.0" >> /work/proj && \
    echo "source: https://github.com/curl/curl/releases/download/curl-8_17_0/curl-8.17.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/curl/curl/releases/download/curl-8_17_0/curl-8.17.0.tar.gz && \
    tar -xzf curl-8.17.0.tar.gz && \
    rm curl-8.17.0.tar.gz && \
    cp -a curl-8.17.0 build-fuzz && \
    cp -a curl-8.17.0 build-cmplog && \
    cp -a curl-8.17.0 build-cov && \
    cp -a curl-8.17.0 build-uftrace && \
    rm -rf curl-8.17.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --with-openssl --without-libpsl && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/src/curl bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static --with-openssl --without-libpsl && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/src/curl bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY curl/fuzz/dict /work/dict
COPY curl/fuzz/in /work/in
COPY curl/fuzz/fuzz.sh /work/fuzz.sh
COPY curl/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --with-openssl --without-libpsl && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/src/curl bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --with-openssl --without-libpsl && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/src/curl bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
