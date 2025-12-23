FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract hiredis 1.3.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: hiredis" > /work/proj && \
    echo "version: 1.3.0" >> /work/proj && \
    echo "source: https://github.com/redis/hiredis/archive/refs/tags/v1.3.0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/redis/hiredis/archive/refs/tags/v1.3.0.tar.gz && \
    tar -xzf v1.3.0.tar.gz && \
    mv v1.3.0 build && \
    rm v1.3.0.tar.gz

WORKDIR /work/build

# Install build dependencies (cmake and file for extract-bc)
RUN apt-get update && \
    apt-get install -y cmake file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build hiredis with WLLVM and static linking
# Using CMake with static library
RUN mkdir build && cd build && \
    CC=wllvm \
    cmake .. \
    -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DDISABLE_TESTS=OFF

RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode files
# Extract from the test binary since it links the library statically
RUN mkdir -p /work/bc && \
    extract-bc build/hiredis-test && \
    mv build/hiredis-test.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
