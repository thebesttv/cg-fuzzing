FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract bzip2 1.0.8 from official GitLab repository

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: bzip2" > /work/proj && \
    echo "version: 1.0.8" >> /work/proj && \
    echo "source: https://gitlab.com/bzip2/bzip2/-/archive/bzip2-1.0.8/bzip2-bzip2-1.0.8.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://gitlab.com/bzip2/bzip2/-/archive/bzip2-1.0.8/bzip2-bzip2-1.0.8.tar.gz && \
    tar -xzf bzip2-bzip2-1.0.8.tar.gz && \
    mv bzip2-bzip2-1.0.8 build && \
    rm bzip2-bzip2-1.0.8.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build bzip2 with WLLVM
# bzip2 uses a simple Makefile, so we override CC and CFLAGS
RUN make clean || true && \
    make -j$(nproc) \
    CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes -Wall -Winline -D_FILE_OFFSET_BITS=64" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    bzip2 bzip2recover

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc bzip2 && \
    mv bzip2.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
