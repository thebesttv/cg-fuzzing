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

# Download and extract lexbor v2.6.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: lexbor" > /work/proj && \
    echo "version: 2.6.0" >> /work/proj && \
    echo "source: https://github.com/lexbor/lexbor/archive/refs/tags/v2.6.0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/lexbor/lexbor/archive/refs/tags/v2.6.0.tar.gz && \
    tar -xzf v2.6.0.tar.gz && \
    mv v2.6.0 build && \
    rm v2.6.0.tar.gz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build with CMake and WLLVM
# Need to use shared library mode for examples due to link order issues with static lib and -lm
RUN mkdir build && cd build && \
    CC=wllvm CXX=wllvm++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DLEXBOR_BUILD_STATIC=OFF \
        -DLEXBOR_BUILD_SHARED=ON \
        -DLEXBOR_BUILD_EXAMPLES=ON \
        -DLEXBOR_BUILD_TESTS=OFF

RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode from the shared library
RUN mkdir -p /work/bc && \
    extract-bc build/liblexbor.so && \
    mv build/liblexbor.so.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
