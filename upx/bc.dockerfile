FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract upx v5.0.2
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/upx/upx/releases/download/v5.0.2/upx-5.0.2-src.tar.xz && \
    tar -xf upx-5.0.2-src.tar.xz && \
    rm upx-5.0.2-src.tar.xz

WORKDIR /home/SVF-tools/upx-5.0.2-src

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
RUN mkdir -p ~/bc && \
    extract-bc build/upx && \
    mv build/upx.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
