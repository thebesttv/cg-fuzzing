FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
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
RUN echo "project: libsodium" > /work/proj && \
    echo "version: 1.0.20" >> /work/proj && \
    echo "source: https://github.com/jedisct1/libsodium/releases/download/1.0.20-RELEASE/libsodium-1.0.20.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/jedisct1/libsodium/releases/download/1.0.20-RELEASE/libsodium-1.0.20.tar.gz && \
    tar -xzf libsodium-1.0.20.tar.gz && \
    rm libsodium-1.0.20.tar.gz && \
    cp -a libsodium-1.0.20 build-fuzz && \
    cp -a libsodium-1.0.20 build-cmplog && \
    cp -a libsodium-1.0.20 build-cov && \
    cp -a libsodium-1.0.20 build-uftrace && \
    rm -rf libsodium-1.0.20

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc) && make check -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/test/default/aead_chacha20poly1305 bin-fuzz

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) && AFL_LLVM_CMPLOG=1 make check -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/test/default/aead_chacha20poly1305 bin-cmplog

# Copy fuzzing resources
COPY libsodium/fuzz/dict /work/dict
COPY libsodium/fuzz/in /work/in
COPY libsodium/fuzz/fuzz.sh /work/fuzz.sh
COPY libsodium/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static && \
    make -j$(nproc) && make check -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/test/default/aead_chacha20poly1305 bin-cov && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --prefix=/work/install-uftrace && \
    make -j$(nproc) && make check -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s build-uftrace/test/default/aead_chacha20poly1305 bin-uftrace && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
