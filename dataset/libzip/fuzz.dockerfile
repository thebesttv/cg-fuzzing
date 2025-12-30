FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake zlib1g-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: libzip" > /work/proj && \
    echo "version: 1.11.4" >> /work/proj && \
    echo "source: https://github.com/nih-at/libzip/archive/refs/tags/v1.11.4.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/nih-at/libzip/archive/refs/tags/v1.11.4.tar.gz && \
    tar -xzf v1.11.4.tar.gz && \
    rm v1.11.4.tar.gz && \
    cp -a libzip-1.11.4 build-fuzz && \
    cp -a libzip-1.11.4 build-cmplog && \
    cp -a libzip-1.11.4 build-cov && \
    cp -a libzip-1.11.4 build-uftrace && \
    rm -rf libzip-1.11.4

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DENABLE_COMMONCRYPTO=OFF \
        -DENABLE_GNUTLS=OFF \
        -DENABLE_MBEDTLS=OFF \
        -DENABLE_OPENSSL=OFF \
        -DENABLE_WINDOWS_CRYPTO=OFF \
        -DENABLE_BZIP2=OFF \
        -DENABLE_LZMA=OFF \
        -DENABLE_ZSTD=OFF \
        -DBUILD_TOOLS=ON \
        -DBUILD_REGRESS=OFF \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_DOC=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/build/src/zipcmp bin-fuzz && \
    /work/bin-fuzz -V || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DENABLE_COMMONCRYPTO=OFF \
        -DENABLE_GNUTLS=OFF \
        -DENABLE_MBEDTLS=OFF \
        -DENABLE_OPENSSL=OFF \
        -DENABLE_WINDOWS_CRYPTO=OFF \
        -DENABLE_BZIP2=OFF \
        -DENABLE_LZMA=OFF \
        -DENABLE_ZSTD=OFF \
        -DBUILD_TOOLS=ON \
        -DBUILD_REGRESS=OFF \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_DOC=OFF && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/build/src/zipcmp bin-cmplog && \
    /work/bin-cmplog -V || true

# Copy fuzzing resources
COPY libzip/fuzz/dict /work/dict
COPY libzip/fuzz/in /work/in
COPY libzip/fuzz/fuzz.sh /work/fuzz.sh
COPY libzip/fuzz/whatsup.sh /work/whatsup.sh
COPY libzip/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY libzip/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY libzip/fuzz/collect-branch.py /work/collect-branch.py
COPY libzip/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh
COPY libzip/fuzz/uftrace-callgraph.py /work/uftrace-callgraph.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping" \
        -DBUILD_SHARED_LIBS=OFF \
        -DENABLE_COMMONCRYPTO=OFF \
        -DENABLE_GNUTLS=OFF \
        -DENABLE_MBEDTLS=OFF \
        -DENABLE_OPENSSL=OFF \
        -DENABLE_WINDOWS_CRYPTO=OFF \
        -DENABLE_BZIP2=OFF \
        -DENABLE_LZMA=OFF \
        -DENABLE_ZSTD=OFF \
        -DBUILD_TOOLS=ON \
        -DBUILD_REGRESS=OFF \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_DOC=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/build/src/zipcmp bin-cov && \
    /work/bin-cov -V || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-pg" \
        -DBUILD_SHARED_LIBS=OFF \
        -DENABLE_COMMONCRYPTO=OFF \
        -DENABLE_GNUTLS=OFF \
        -DENABLE_MBEDTLS=OFF \
        -DENABLE_OPENSSL=OFF \
        -DENABLE_WINDOWS_CRYPTO=OFF \
        -DENABLE_BZIP2=OFF \
        -DENABLE_LZMA=OFF \
        -DENABLE_ZSTD=OFF \
        -DBUILD_TOOLS=ON \
        -DBUILD_REGRESS=OFF \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_DOC=OFF \
        -DCMAKE_INSTALL_PREFIX=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/zipcmp bin-uftrace && \
    /work/bin-uftrace -V || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
