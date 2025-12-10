FROM svftools/svf:latest

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
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/zlib-ng/minizip-ng/archive/refs/tags/4.0.10.tar.gz && \
    tar -xzf 4.0.10.tar.gz && \
    rm 4.0.10.tar.gz

WORKDIR /home/SVF-tools/minizip-ng-4.0.10

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
RUN mkdir -p ~/bc && \
    extract-bc build/minizip && \
    mv build/minizip.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
