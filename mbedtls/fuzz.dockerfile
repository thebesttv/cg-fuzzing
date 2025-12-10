FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract mbedtls 3.6.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.2/mbedtls-3.6.2.tar.bz2 && \
    tar -xjf mbedtls-3.6.2.tar.bz2 && \
    rm mbedtls-3.6.2.tar.bz2

WORKDIR /src/mbedtls-3.6.2

# Build with afl-clang-fast using cmake
RUN mkdir build && cd build && \
    CC=afl-clang-fast CXX=afl-clang-fast++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-Wl,--allow-multiple-definition" \
        -DENABLE_PROGRAMS=ON \
        -DENABLE_TESTING=OFF \
        -DUSE_STATIC_MBEDTLS_LIBRARY=ON \
        -DUSE_SHARED_MBEDTLS_LIBRARY=OFF

RUN cd build && make -j$(nproc)

# Copy binary
RUN cp build/programs/pkey/pk_decrypt /out/pk_decrypt

# Build CMPLOG version
WORKDIR /src
RUN rm -rf mbedtls-3.6.2 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.2/mbedtls-3.6.2.tar.bz2 && \
    tar -xjf mbedtls-3.6.2.tar.bz2 && \
    rm mbedtls-3.6.2.tar.bz2

WORKDIR /src/mbedtls-3.6.2

# Build with afl-clang-fast and CMPLOG
RUN mkdir build && cd build && \
    CC=afl-clang-fast CXX=afl-clang-fast++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-Wl,--allow-multiple-definition" \
        -DENABLE_PROGRAMS=ON \
        -DENABLE_TESTING=OFF \
        -DUSE_STATIC_MBEDTLS_LIBRARY=ON \
        -DUSE_SHARED_MBEDTLS_LIBRARY=OFF

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Copy CMPLOG binary
RUN cp build/programs/pkey/pk_decrypt /out/pk_decrypt.cmplog

# Copy fuzzing resources
COPY mbedtls/fuzz/dict /out/dict
COPY mbedtls/fuzz/in /out/in
COPY mbedtls/fuzz/fuzz.sh /out/fuzz.sh
COPY mbedtls/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/pk_decrypt /out/pk_decrypt.cmplog && \
    file /out/pk_decrypt

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing mbedtls'"]
