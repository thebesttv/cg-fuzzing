FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract flex v2.6.4

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: flex" > /work/proj && \
    echo "version: 2.6.4" >> /work/proj && \
    echo "source: https://github.com/westes/flex/releases/download/v2.6.4/flex-2.6.4.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/westes/flex/releases/download/v2.6.4/flex-2.6.4.tar.gz && \
    tar -xzf flex-2.6.4.tar.gz && \
    mv flex-2.6.4 build && \
    rm flex-2.6.4.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc, m4 for flex build)
RUN apt-get update && \
    apt-get install -y file m4 bison help2man && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

# Build flex
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc src/flex && \
    mv src/flex.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
