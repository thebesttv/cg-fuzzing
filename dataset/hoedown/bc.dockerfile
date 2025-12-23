FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract hoedown v3.0.7

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: hoedown" > /work/proj && \
    echo "version: 3.0.7" >> /work/proj && \
    echo "source: https://github.com/hoedown/hoedown/archive/refs/tags/3.0.7.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/hoedown/hoedown/archive/refs/tags/3.0.7.tar.gz -O hoedown-3.0.7.tar.gz && \
    tar -xzf hoedown-3.0.7.tar.gz && \
    mv hoedown-3.0.7 build && \
    rm hoedown-3.0.7.tar.gz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build with wllvm and static linking
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes -ansi -pedantic -Wall -Wextra -Wno-unused-parameter" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make hoedown

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc hoedown && \
    mv hoedown.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
