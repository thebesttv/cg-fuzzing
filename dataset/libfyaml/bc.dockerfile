FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libfyaml v0.9

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: libfyaml" > /work/proj && \
    echo "version: 0.9" >> /work/proj && \
    echo "source: https://github.com/pantoniou/libfyaml/releases/download/v0.9/libfyaml-0.9.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/pantoniou/libfyaml/releases/download/v0.9/libfyaml-0.9.tar.gz && \
    tar -xzf libfyaml-0.9.tar.gz && \
    mv libfyaml-0.9 build && \
    rm libfyaml-0.9.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file autoconf automake libtool pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

# Build libfyaml
RUN make -j$(nproc)

# Create bc directory and extract bitcode files from fy-tool
RUN mkdir -p /work/bc && \
    extract-bc src/fy-tool && \
    mv src/fy-tool.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
