FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract capstone 5.0.3 (stable version instead of alpha)
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/capstone-engine/capstone/archive/refs/tags/5.0.3.tar.gz && \
    tar -xzf 5.0.3.tar.gz && \
    rm 5.0.3.tar.gz

WORKDIR /home/SVF-tools/capstone-5.0.3

# Build with WLLVM using cmake
RUN mkdir build && cd build && \
    CC=wllvm CXX=wllvm++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DCAPSTONE_BUILD_STATIC=ON \
        -DCAPSTONE_BUILD_CSTOOL=ON \
        -DCAPSTONE_BUILD_TESTS=OFF \
        -DCAPSTONE_BUILD_CSTEST=OFF

RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc build/cstool && \
    mv build/cstool.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
