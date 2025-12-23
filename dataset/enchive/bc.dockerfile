FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract enchive v3.5

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: enchive" > /work/proj && \
    echo "version: 3.5" >> /work/proj && \
    echo "source: https://github.com/skeeto/enchive/archive/refs/tags/3.5.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/skeeto/enchive/archive/refs/tags/3.5.tar.gz && \
    tar -xzf 3.5.tar.gz && \
    mv 3.5 build && \
    rm 3.5.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build with static linking and WLLVM
# Override CC in make command since Makefile has CC = cc
RUN make CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

# Create bc directory and extract bitcode
RUN mkdir -p /work/bc && \
    extract-bc enchive && \
    mv enchive.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
