FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake zlib1g-dev python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Build static zlib for static linking
RUN cd /tmp && \
    wget https://www.zlib.net/zlib-1.3.1.tar.gz && \
    tar -xzf zlib-1.3.1.tar.gz && \
    cd zlib-1.3.1 && \
    ./configure --static && \
    make -j$(nproc) && \
    make install && \
    rm -rf /tmp/zlib-1.3.1*

# Download zziplib from GitHub (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/gdraheim/zziplib/archive/refs/tags/v0.13.80.tar.gz && \
    tar -xzf v0.13.80.tar.gz && \
    rm v0.13.80.tar.gz

WORKDIR /src/zziplib-0.13.80

# Build zziplib with afl-clang-lto for fuzzing
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_TESTS=OFF

RUN cd build && make unzzip-big unzip-mem -j$(nproc)

# Install the binaries (unzzip-big has zzcat-like functionality)
RUN cp build/bins/unzzip-big /out/unzzip-big && \
    cp build/bins/unzip-mem /out/unzip-mem

# Build CMPLOG versions for better fuzzing
WORKDIR /src
RUN rm -rf zziplib-0.13.80 && \
    wget https://github.com/gdraheim/zziplib/archive/refs/tags/v0.13.80.tar.gz && \
    tar -xzf v0.13.80.tar.gz && \
    rm v0.13.80.tar.gz

WORKDIR /src/zziplib-0.13.80

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_TESTS=OFF

RUN cd build && AFL_LLVM_CMPLOG=1 make unzzip-big unzip-mem -j$(nproc)

# Install CMPLOG binaries
RUN cp build/bins/unzzip-big /out/unzzip-big.cmplog && \
    cp build/bins/unzip-mem /out/unzip-mem.cmplog

# Copy fuzzing resources
COPY dataset/zziplib/fuzz/dict /out/dict
COPY dataset/zziplib/fuzz/in /out/in
COPY dataset/zziplib/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/zziplib/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/unzzip-big /out/unzzip-big.cmplog /out/unzip-mem /out/unzip-mem.cmplog && \
    file /out/unzzip-big

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing zziplib'"]
