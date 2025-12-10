FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract c-blosc v1.21.6
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/Blosc/c-blosc/archive/refs/tags/v1.21.6.tar.gz && \
    tar -xzf v1.21.6.tar.gz && \
    rm v1.21.6.tar.gz

WORKDIR /home/SVF-tools/c-blosc-1.21.6

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build with CMake and WLLVM (need shared for bench)
RUN mkdir build && cd build && \
    CC=wllvm CXX=wllvm++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DBUILD_STATIC=ON \
        -DBUILD_SHARED=ON \
        -DBUILD_TESTS=OFF \
        -DBUILD_FUZZERS=OFF \
        -DBUILD_BENCHMARKS=ON

RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode from shared library
RUN mkdir -p ~/bc && \
    extract-bc build/blosc/libblosc.so && \
    mv build/blosc/libblosc.so.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
