FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract xz v5.8.1

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: xz" > /work/proj && \
    echo "version: 5.8.1" >> /work/proj && \
    echo "source: https://github.com/tukaani-project/xz/releases/download/v5.8.1/xz-5.8.1.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/tukaani-project/xz/releases/download/v5.8.1/xz-5.8.1.tar.gz && \
    tar -xzf xz-5.8.1.tar.gz && \
    mv xz-5.8.1 build && \
    rm xz-5.8.1.tar.gz

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
    ./configure --disable-shared --enable-static

# Build xz
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc src/xz/xz && \
    mv src/xz/xz.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
