FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake python3 uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: mbedtls" > /work/proj && \
    echo "version: 3.6.2" >> /work/proj && \
    echo "source: https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.2/mbedtls-3.6.2.tar.bz2" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.2/mbedtls-3.6.2.tar.bz2 && \
    tar -xjf mbedtls-3.6.2.tar.bz2 && \
    rm mbedtls-3.6.2.tar.bz2 && \
    cp -a mbedtls-3.6.2 build-fuzz && \
    cp -a mbedtls-3.6.2 build-cmplog && \
    cp -a mbedtls-3.6.2 build-cov && \
    cp -a mbedtls-3.6.2 build-uftrace && \
    rm -rf mbedtls-3.6.2

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DENABLE_PROGRAMS=ON \
        -DENABLE_TESTING=OFF \
        -DUSE_STATIC_MBEDTLS_LIBRARY=ON \
        -DUSE_SHARED_MBEDTLS_LIBRARY=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/build/programs/pkey/pk_decrypt bin-fuzz && \
    /work/bin-fuzz || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DENABLE_PROGRAMS=ON \
        -DENABLE_TESTING=OFF \
        -DUSE_STATIC_MBEDTLS_LIBRARY=ON \
        -DUSE_SHARED_MBEDTLS_LIBRARY=OFF && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/build/programs/pkey/pk_decrypt bin-cmplog && \
    /work/bin-cmplog || true

# Copy fuzzing resources
COPY mbedtls/fuzz/dict /work/dict
COPY mbedtls/fuzz/in /work/in
COPY mbedtls/fuzz/fuzz.sh /work/fuzz.sh
COPY mbedtls/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
        -DENABLE_PROGRAMS=ON \
        -DENABLE_TESTING=OFF \
        -DUSE_STATIC_MBEDTLS_LIBRARY=ON \
        -DUSE_SHARED_MBEDTLS_LIBRARY=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/build/programs/pkey/pk_decrypt bin-cov && \
    /work/bin-cov || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-pg -Wl,--allow-multiple-definition" \
        -DCMAKE_INSTALL_PREFIX=/work/install-uftrace \
        -DENABLE_PROGRAMS=ON \
        -DENABLE_TESTING=OFF \
        -DUSE_STATIC_MBEDTLS_LIBRARY=ON \
        -DUSE_SHARED_MBEDTLS_LIBRARY=OFF && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/pk_decrypt bin-uftrace && \
    /work/bin-uftrace || true && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
