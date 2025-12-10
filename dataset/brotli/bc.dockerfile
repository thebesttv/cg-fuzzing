FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract brotli v1.2.0
WORKDIR /home/SVF-tools
RUN wget https://github.com/google/brotli/archive/refs/tags/v1.2.0.tar.gz && \
    tar -xzf v1.2.0.tar.gz && \
    rm v1.2.0.tar.gz

WORKDIR /home/SVF-tools/brotli-1.2.0

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
        -DBUILD_SHARED_LIBS=OFF \
        -DCMAKE_BUILD_TYPE=Debug

RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc build/brotli && \
    mv build/brotli.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
