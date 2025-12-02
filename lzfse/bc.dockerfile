FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract lzfse 1.0
WORKDIR /home/SVF-tools
RUN wget https://github.com/lzfse/lzfse/archive/refs/tags/lzfse-1.0.tar.gz && \
    tar -xzf lzfse-1.0.tar.gz && \
    rm lzfse-1.0.tar.gz

WORKDIR /home/SVF-tools/lzfse-lzfse-1.0

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build using CMake with WLLVM
RUN mkdir build && cd build && \
    CC=wllvm \
    cmake .. \
    -DCMAKE_C_FLAGS="-g -O0" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF

RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc build/lzfse && \
    mv build/lzfse.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
