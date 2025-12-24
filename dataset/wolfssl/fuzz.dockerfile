FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: wolfssl" > /work/proj && \
    echo "version: 5.7.4" >> /work/proj && \
    echo "source: https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.7.4-stable.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.7.4-stable.tar.gz && \
    tar -xzf v5.7.4-stable.tar.gz && \
    rm v5.7.4-stable.tar.gz && \
    cp -a wolfssl-5.7.4-stable build-fuzz && \
    cp -a wolfssl-5.7.4-stable build-cmplog && \
    cp -a wolfssl-5.7.4-stable build-cov && \
    cp -a wolfssl-5.7.4-stable build-uftrace && \
    rm -rf wolfssl-5.7.4-stable

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN ./autogen.sh && \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --enable-crypttests && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/examples/asn1/asn1 bin-fuzz && \
    /work/bin-fuzz --help 2>&1 | head -5 || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN ./autogen.sh && \
    AFL_LLVM_CMPLOG=1 CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --enable-crypttests && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/examples/asn1/asn1 bin-cmplog && \
    /work/bin-cmplog --help 2>&1 | head -5 || true

# Copy fuzzing resources
COPY wolfssl/fuzz/dict /work/dict
COPY wolfssl/fuzz/in /work/in
COPY wolfssl/fuzz/fuzz.sh /work/fuzz.sh
COPY wolfssl/fuzz/whatsup.sh /work/whatsup.sh
COPY wolfssl/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN ./autogen.sh && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --enable-crypttests && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/examples/asn1/asn1 bin-cov && \
    /work/bin-cov --help 2>&1 | head -5 || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN ./autogen.sh && \
    CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --enable-crypttests && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/examples/asn1/asn1 bin-uftrace && \
    /work/bin-uftrace --help 2>&1 | head -5 || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
