FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract squashfs-tools 4.7.4
WORKDIR /home/SVF-tools
RUN wget https://github.com/plougher/squashfs-tools/releases/download/4.7.4/squashfs-tools-4.7.4.tar.gz && \
    tar -xzf squashfs-tools-4.7.4.tar.gz && \
    rm squashfs-tools-4.7.4.tar.gz

WORKDIR /home/SVF-tools/squashfs-tools-4.7.4/squashfs-tools

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
RUN mkdir -p ~/bc && \
    extract-bc unsquashfs && \
    mv unsquashfs.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
