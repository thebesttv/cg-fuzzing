FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract jsmn v1.1.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: jsmn" > /work/proj && \
    echo "version: 1.1.0" >> /work/proj && \
    echo "source: https://github.com/zserge/jsmn/archive/refs/tags/v1.1.0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/zserge/jsmn/archive/refs/tags/v1.1.0.tar.gz && \
    tar -xzf v1.1.0.tar.gz && \
    mv v1.1.0 build && \
    rm v1.1.0.tar.gz

WORKDIR /work/build

# Build jsondump example as a standalone static binary
# jsmn is header-only, so we compile jsondump.c with jsmn.h included
RUN wllvm \
    -g -O0 -Xclang -disable-llvm-passes \
    -DJSMN_PARENT_LINKS \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o jsondump \
    example/jsondump.c

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc jsondump && \
    mv jsondump.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
