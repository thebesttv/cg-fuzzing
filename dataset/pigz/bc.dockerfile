FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract pigz v2.8

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: pigz" > /work/proj && \
    echo "version: 2.8" >> /work/proj && \
    echo "source: https://github.com/madler/pigz/archive/refs/tags/v2.8.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/madler/pigz/archive/refs/tags/v2.8.tar.gz && \
    tar -xzf v2.8.tar.gz && \
    mv v2.8 build && \
    rm v2.8.tar.gz

WORKDIR /work/build

# Build pigz with WLLVM
# pigz uses a simple Makefile
RUN make clean || true && \
    make -j$(nproc) \
    CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc pigz && \
    mv pigz.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
