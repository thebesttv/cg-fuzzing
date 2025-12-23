FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract lzop v1.04

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: lzop" > /work/proj && \
    echo "version: 1.04" >> /work/proj && \
    echo "source: https://www.lzop.org/download/lzop-1.04.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.lzop.org/download/lzop-1.04.tar.gz && \
    tar -xzf lzop-1.04.tar.gz && \
    mv lzop-1.04 build && \
    rm lzop-1.04.tar.gz

# Download and build lzo library (dependency)
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.oberhumer.com/opensource/lzo/download/lzo-2.10.tar.gz && \
    tar -xzf lzo-2.10.tar.gz && \
    rm lzo-2.10.tar.gz

WORKDIR /work/build

# Build lzo library with wllvm
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)
RUN make install

# Build lzop
WORKDIR /work/build

RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-asm

RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc src/lzop && \
    mv src/lzop.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
