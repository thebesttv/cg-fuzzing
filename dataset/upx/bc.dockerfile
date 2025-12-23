FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract upx v5.0.2

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: upx" > /work/proj && \
    echo "version: 5.0.2" >> /work/proj && \
    echo "source: https://github.com/upx/upx/releases/download/v5.0.2/upx-5.0.2-src.tar.xz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/upx/upx/releases/download/v5.0.2/upx-5.0.2-src.tar.xz && \
    tar -xf upx-5.0.2-src.tar.xz && \
    mv upx-5.0.2-src build && \
    rm upx-5.0.2-src.tar.xz

WORKDIR /work/build

# Install build dependencies (file for extract-bc, cmake for building)
RUN apt-get update && \
    apt-get install -y file cmake ninja-build zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM using CMake
RUN mkdir build && cd build && \
    CC=wllvm CXX=wllvm++ \
    cmake .. -G Ninja \
        -DCMAKE_C_FLAGS="-g -O0" \
        -DCMAKE_CXX_FLAGS="-g -O0" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DUPX_CONFIG_DISABLE_WERROR=ON

# Build upx
RUN cd build && ninja -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc build/upx && \
    mv build/upx.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
