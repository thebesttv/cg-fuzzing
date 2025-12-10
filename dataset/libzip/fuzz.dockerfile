FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libzip v1.11.4 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/nih-at/libzip/archive/refs/tags/v1.11.4.tar.gz && \
    tar -xzf v1.11.4.tar.gz && \
    rm v1.11.4.tar.gz

WORKDIR /src/libzip-1.11.4

# Build zipcmp with afl-clang-lto for fuzzing (main target binary)
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
        -DBUILD_DOC=OFF

RUN cd build && make -j$(nproc)

# Install the zipcmp binary
RUN cp build/src/zipcmp /out/zipcmp

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf libzip-1.11.4 && \
    wget https://github.com/nih-at/libzip/archive/refs/tags/v1.11.4.tar.gz && \
    tar -xzf v1.11.4.tar.gz && \
    rm v1.11.4.tar.gz

WORKDIR /src/libzip-1.11.4

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
        -DBUILD_DOC=OFF

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp build/src/zipcmp /out/zipcmp.cmplog

# Copy fuzzing resources
COPY dataset/libzip/fuzz/dict /out/dict
COPY dataset/libzip/fuzz/in /out/in
COPY dataset/libzip/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/libzip/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/zipcmp /out/zipcmp.cmplog && \
    file /out/zipcmp && \
    /out/zipcmp -V || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing zipcmp'"]
