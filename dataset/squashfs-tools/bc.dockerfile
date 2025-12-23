FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract squashfs-tools 4.7.4

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: squashfs-tools" > /work/proj && \
    echo "version: 4.7.4" >> /work/proj && \
    echo "source: https://github.com/plougher/squashfs-tools/releases/download/4.7.4/squashfs-tools-4.7.4.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/plougher/squashfs-tools/releases/download/4.7.4/squashfs-tools-4.7.4.tar.gz && \
    tar -xzf squashfs-tools-4.7.4.tar.gz && \
    mv squashfs-tools-4.7.4 build && \
    rm squashfs-tools-4.7.4.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc, zlib and compression libs)
RUN apt-get update && \
    apt-get install -y file zlib1g-dev liblzo2-dev liblz4-dev libzstd-dev liblzma-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build unsquashfs with WLLVM and static linking
# Squashfs-tools uses a simple Makefile
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make -j$(nproc) unsquashfs

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc unsquashfs && \
    mv unsquashfs.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
