FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract base64 v0.5.2

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: base64" > /work/proj && \
    echo "version: 0.5.2" >> /work/proj && \
    echo "source: https://github.com/aklomp/base64/archive/refs/tags/v0.5.2.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/aklomp/base64/archive/refs/tags/v0.5.2.tar.gz && \
    tar -xzf v0.5.2.tar.gz && \
    mv v0.5.2 build && \
    rm v0.5.2.tar.gz

WORKDIR /work/build

# Install build dependencies (cmake and file for extract-bc)
RUN apt-get update && \
    apt-get install -y cmake file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build base64 with WLLVM and static linking
RUN mkdir build && cd build && \
    CC=wllvm \
    cmake .. \
    -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DBASE64_BUILD_CLI=ON

RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc build/bin/base64 && \
    mv build/bin/base64.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
