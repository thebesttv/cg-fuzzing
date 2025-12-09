FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract zlib-ng 2.3.1
WORKDIR /home/SVF-tools
RUN wget https://github.com/zlib-ng/zlib-ng/archive/refs/tags/2.3.1.tar.gz && \
    tar -xzf 2.3.1.tar.gz && \
    rm 2.3.1.tar.gz

WORKDIR /home/SVF-tools/zlib-ng-2.3.1

# Install build dependencies (file for extract-bc, cmake for build)
RUN apt-get update && \
    apt-get install -y file cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build zlib-ng with WLLVM using CMake
# Build minigzip and minideflate as CLI tools
RUN mkdir build && cd build && \
    CC=wllvm \
    CXX=wllvm++ \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DZLIB_COMPAT=ON \
        -DWITH_GTEST=OFF

RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    cd build && \
    extract-bc minigzip && \
    mv minigzip.bc ~/bc/ && \
    extract-bc minideflate && \
    mv minideflate.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
