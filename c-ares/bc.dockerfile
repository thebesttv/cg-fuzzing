FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract c-ares v1.34.5
WORKDIR /home/SVF-tools
RUN wget https://github.com/c-ares/c-ares/releases/download/v1.34.5/c-ares-1.34.5.tar.gz && \
    tar -xzf c-ares-1.34.5.tar.gz && \
    rm c-ares-1.34.5.tar.gz

WORKDIR /home/SVF-tools/c-ares-1.34.5

# Install build dependencies (file for extract-bc, cmake for build)
RUN apt-get update && \
    apt-get install -y file cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build with CMake using WLLVM
RUN mkdir build && cd build && \
    CC=wllvm \
    CXX=wllvm++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DCARES_STATIC=ON \
        -DCARES_SHARED=OFF \
        -DCARES_BUILD_TOOLS=ON \
        -DCMAKE_BUILD_TYPE=Debug

RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode files from adig and ahost
RUN mkdir -p ~/bc && \
    extract-bc build/bin/adig && \
    mv build/bin/adig.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
