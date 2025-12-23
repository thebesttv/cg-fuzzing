FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract lzo 2.10

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: lzo" > /work/proj && \
    echo "version: 2.10" >> /work/proj && \
    echo "source: https://www.oberhumer.com/opensource/lzo/download/lzo-2.10.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.oberhumer.com/opensource/lzo/download/lzo-2.10.tar.gz && \
    tar -xzf lzo-2.10.tar.gz && \
    mv lzo-2.10 build && \
    rm lzo-2.10.tar.gz

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

# Build lzo
RUN make -j$(nproc)

# Build lzopack example manually - need to add include paths properly
RUN cd examples && \
    wllvm -g -O0 -Xclang -disable-llvm-passes -I. -I../include -I.. -static -Wl,--allow-multiple-definition \
        -o lzopack lzopack.c ../src/.libs/liblzo2.a

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc examples/lzopack && \
    mv examples/lzopack.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
