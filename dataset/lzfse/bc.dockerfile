FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract lzfse 1.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: lzfse" > /work/proj && \
    echo "version: 1.0" >> /work/proj && \
    echo "source: https://github.com/lzfse/lzfse/archive/refs/tags/lzfse-1.0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/lzfse/lzfse/archive/refs/tags/lzfse-1.0.tar.gz && \
    tar -xzf lzfse-1.0.tar.gz && \
    mv lzfse-1.0 build && \
    rm lzfse-1.0.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build using CMake with WLLVM
RUN mkdir build && cd build && \
    CC=wllvm \
    cmake .. \
    -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF

RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc build/lzfse && \
    mv build/lzfse.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
