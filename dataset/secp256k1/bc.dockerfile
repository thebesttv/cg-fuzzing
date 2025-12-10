FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract secp256k1 v0.7.0
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v0.7.0.tar.gz && \
    tar -xzf v0.7.0.tar.gz && \
    rm v0.7.0.tar.gz

WORKDIR /home/SVF-tools/secp256k1-0.7.0

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create build directory and configure with CMake
RUN mkdir build && cd build && \
    CC=wllvm CXX=wllvm++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DSECP256K1_ENABLE_MODULE_ECDH=ON \
        -DSECP256K1_ENABLE_MODULE_RECOVERY=ON \
        -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON \
        -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON \
        -DSECP256K1_ENABLE_MODULE_ELLSWIFT=ON \
        -DSECP256K1_BUILD_BENCHMARK=ON \
        -DSECP256K1_BUILD_EXAMPLES=ON

# Build secp256k1
RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc build/bin/bench && \
    mv build/bin/bench.bc ~/bc/ && \
    extract-bc build/bin/bench_internal && \
    mv build/bin/bench_internal.bc ~/bc/

# Verify that bc files were created and binary is static
RUN ls -la ~/bc/ && \
    file build/bin/bench && \
    ldd build/bin/bench 2>&1 || echo "Binary is statically linked"
