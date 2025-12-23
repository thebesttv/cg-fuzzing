FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract fribidi v1.0.15

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: fribidi" > /work/proj && \
    echo "version: 1.0.15" >> /work/proj && \
    echo "source: https://github.com/fribidi/fribidi/releases/download/v1.0.15/fribidi-1.0.15.tar.xz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/fribidi/fribidi/releases/download/v1.0.15/fribidi-1.0.15.tar.xz && \
    tar -xf fribidi-1.0.15.tar.xz && \
    mv fribidi-1.0.15 build && \
    rm fribidi-1.0.15.tar.xz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

# Build
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc bin/fribidi && \
    mv bin/fribidi.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
