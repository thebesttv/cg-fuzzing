FROM svftools/svf:latest

# 1. Install WLLVM and build dependencies
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file cmake zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# 2. Download libzip source code (v1.11.4)
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/nih-at/libzip/archive/refs/tags/v1.11.4.tar.gz && \
    tar -xzf v1.11.4.tar.gz && \
    rm v1.11.4.tar.gz

WORKDIR /home/SVF-tools/libzip-1.11.4

# 3. Build with WLLVM using CMake
# Disable optional compression methods to avoid dynamic linking issues
RUN mkdir build && cd build && \
    CC=wllvm CXX=wllvm++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
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
        -DBUILD_DOC=OFF

RUN cd build && make -j$(nproc)

# 4. Extract bitcode files (zipcmp is a good CLI tool for fuzzing)
RUN mkdir -p ~/bc && \
    extract-bc build/src/zipcmp && \
    mv build/src/zipcmp.bc ~/bc/

# 5. Verify
RUN ls -la ~/bc/
