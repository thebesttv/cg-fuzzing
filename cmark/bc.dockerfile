FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract cmark 0.31.1
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/commonmark/cmark/archive/refs/tags/0.31.1.tar.gz && \
    tar -xzf 0.31.1.tar.gz && \
    rm 0.31.1.tar.gz

WORKDIR /home/SVF-tools/cmark-0.31.1

# Install build dependencies (file for extract-bc, cmake for building)
RUN apt-get update && \
    apt-get install -y file cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build cmark with WLLVM using CMake
RUN mkdir build && cd build && \
    CC=wllvm \
    cmake .. \
    -DCMAKE_C_FLAGS="-g -O0" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMARK_STATIC=ON \
    -DCMARK_TESTS=OFF

RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc build/src/cmark && \
    mv build/src/cmark.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
