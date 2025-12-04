FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libjpeg-turbo 3.1.2
WORKDIR /home/SVF-tools
RUN wget https://github.com/libjpeg-turbo/libjpeg-turbo/archive/refs/tags/3.1.2.tar.gz && \
    tar -xzf 3.1.2.tar.gz && \
    rm 3.1.2.tar.gz

WORKDIR /home/SVF-tools/libjpeg-turbo-3.1.2

# Install build dependencies (file for extract-bc, cmake for build, nasm for SIMD)
RUN apt-get update && \
    apt-get install -y file cmake nasm && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with CMake and WLLVM
# Build static library and tools
RUN mkdir build && cd build && \
    CC=wllvm \
    CXX=wllvm++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DENABLE_SHARED=OFF \
        -DENABLE_STATIC=ON \
        -DWITH_TURBOJPEG=OFF

# Build libjpeg-turbo
RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode files for djpeg (JPEG decoder - good for fuzzing)
# Note: When building static only, the binary is named djpeg-static
RUN mkdir -p ~/bc && \
    extract-bc build/djpeg-static && \
    mv build/djpeg-static.bc ~/bc/djpeg.bc

# Verify that bc files were created
RUN ls -la ~/bc/
