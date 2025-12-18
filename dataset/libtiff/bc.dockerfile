FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libtiff v4.7.0
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://download.osgeo.org/libtiff/tiff-4.7.0.tar.gz && \
    tar -xzf tiff-4.7.0.tar.gz && \
    rm tiff-4.7.0.tar.gz

WORKDIR /home/SVF-tools/tiff-4.7.0

# Install build dependencies (file for extract-bc, static libs for linking)
RUN apt-get update && \
    apt-get install -y file cmake zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build with CMake for static linking with WLLVM
# Disable external codec dependencies for simpler static build
RUN mkdir cmake_build && cd cmake_build && \
    CC=wllvm CXX=wllvm++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_CXX_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DBUILD_SHARED_LIBS=OFF \
        -Dtiff-docs=OFF \
        -Dtiff-tests=OFF \
        -Djpeg=OFF \
        -Djbig=OFF \
        -Dlerc=OFF \
        -Dlzma=OFF \
        -Dzstd=OFF \
        -Dwebp=OFF \
        -Dzlib=OFF

RUN cd cmake_build && make -j$(nproc)

# Create bc directory and extract bitcode files from tiffinfo
RUN mkdir -p ~/bc && \
    extract-bc cmake_build/tools/tiffinfo && \
    mv cmake_build/tools/tiffinfo.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
