FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y cmake file python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract mbedtls 3.6.2 (latest LTS version)

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: mbedtls" > /work/proj && \
    echo "version: 3.6.2" >> /work/proj && \
    echo "source: https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.2/mbedtls-3.6.2.tar.bz2" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.2/mbedtls-3.6.2.tar.bz2 && \
    tar -xjf mbedtls-3.6.2.tar.bz2 && \
    mv mbedtls-3.6.2 build && \
    rm mbedtls-3.6.2.tar.bz2

WORKDIR /work/build

# Build with WLLVM using cmake
RUN mkdir build && cd build && \
    CC=wllvm CXX=wllvm++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DENABLE_PROGRAMS=ON \
        -DENABLE_TESTING=OFF \
        -DUSE_STATIC_MBEDTLS_LIBRARY=ON \
        -DUSE_SHARED_MBEDTLS_LIBRARY=OFF

RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode files from key utilities
RUN mkdir -p /work/bc && \
    extract-bc build/programs/pkey/pk_decrypt && \
    mv build/programs/pkey/pk_decrypt.bc /work/bc/ || true

# Verify that bc files were created
RUN ls -la /work/bc/
