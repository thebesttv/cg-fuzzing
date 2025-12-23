FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y cmake zlib1g-dev libbz2-dev liblzma-dev libzstd-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract minizip-ng v4.0.10

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: minizip-ng" > /work/proj && \
    echo "version: 4.0.10" >> /work/proj && \
    echo "source: https://github.com/zlib-ng/minizip-ng/archive/refs/tags/4.0.10.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/zlib-ng/minizip-ng/archive/refs/tags/4.0.10.tar.gz && \
    tar -xzf 4.0.10.tar.gz && \
    mv 4.0.10 build && \
    rm 4.0.10.tar.gz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build with CMake and WLLVM
RUN mkdir build && cd build && \
    CC=wllvm CXX=wllvm++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DMZ_BUILD_TESTS=ON \
        -DMZ_BUILD_UNIT_TESTS=OFF \
        -DMZ_COMPAT=OFF \
        -DMZ_FETCH_LIBS=OFF

RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode from minizip CLI
RUN mkdir -p /work/bc && \
    extract-bc build/minizip && \
    mv build/minizip.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
