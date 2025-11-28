FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract mujs 1.3.8
WORKDIR /home/SVF-tools
RUN wget https://github.com/ArtifexSoftware/mujs/archive/refs/tags/1.3.8.tar.gz && \
    tar -xzf 1.3.8.tar.gz && \
    rm 1.3.8.tar.gz

WORKDIR /home/SVF-tools/mujs-1.3.8

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file libreadline-dev curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build mujs with WLLVM (static linking)
# mujs uses a simple Makefile - build object file first
RUN make -j$(nproc) \
    CC=wllvm \
    CFLAGS="-g -O0" \
    build/release/libmujs.o

# Link statically
RUN wllvm -g -O0 -static -Wl,--allow-multiple-definition \
    -o build/release/mujs main.c build/release/libmujs.o -lm

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc build/release/mujs && \
    mv build/release/mujs.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
