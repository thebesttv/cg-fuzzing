FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract json-c 0.18

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: json-c" > /work/proj && \
    echo "version: 0.18" >> /work/proj && \
    echo "source: https://github.com/json-c/json-c/archive/refs/tags/json-c-0.18-20240915.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/json-c/json-c/archive/refs/tags/json-c-0.18-20240915.tar.gz && \
    tar -xzf json-c-0.18-20240915.tar.gz && \
    mv json-c-0.18-20240915 build && \
    rm json-c-0.18-20240915.tar.gz

WORKDIR /work/build

# Install build dependencies (cmake and file for extract-bc)
RUN apt-get update && \
    apt-get install -y cmake file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build json-c with WLLVM and static linking
RUN mkdir build && cd build && \
    CC=wllvm \
    cmake .. \
    -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_APPS=ON

RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc build/apps/json_parse && \
    mv build/apps/json_parse.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
