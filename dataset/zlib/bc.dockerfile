FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract zlib 1.3.1

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: zlib" > /work/proj && \
    echo "version: 1.3.1" >> /work/proj && \
    echo "source: https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz && \
    tar -xzf zlib-1.3.1.tar.gz && \
    mv zlib-1.3.1 build && \
    rm zlib-1.3.1.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --static

# Build zlib and minigzip
RUN make -j$(nproc)

# Build minigzip (the CLI tool for fuzzing)
RUN make -j$(nproc) minigzip

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc minigzip && \
    mv minigzip.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
