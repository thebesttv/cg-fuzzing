FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract mujs 1.3.8

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: mujs" > /work/proj && \
    echo "version: 1.3.8" >> /work/proj && \
    echo "source: https://github.com/ArtifexSoftware/mujs/archive/refs/tags/1.3.8.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/ArtifexSoftware/mujs/archive/refs/tags/1.3.8.tar.gz && \
    tar -xzf 1.3.8.tar.gz && \
    mv 1.3.8 build && \
    rm 1.3.8.tar.gz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file libreadline-dev curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build mujs with WLLVM (static linking)
# mujs uses a simple Makefile - build object file first
RUN make -j$(nproc) \
    CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    build/release/libmujs.o

# Link statically
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -static -Wl,--allow-multiple-definition \
    -o build/release/mujs main.c build/release/libmujs.o -lm

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc build/release/mujs && \
    mv build/release/mujs.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
