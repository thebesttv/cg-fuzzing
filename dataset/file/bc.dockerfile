FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract file 5.46

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: file" > /work/proj && \
    echo "version: 5.46" >> /work/proj && \
    echo "source: https://astron.com/pub/file/file-5.46.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://astron.com/pub/file/file-5.46.tar.gz && \
    tar -xzf file-5.46.tar.gz && \
    mv file-5.46 build && \
    rm file-5.46.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc, zlib for compression support)
RUN apt-get update && \
    apt-get install -y file zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

# Build file
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc src/file && \
    mv src/file.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
