FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract dosfstools 4.2

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: dosfstools" > /work/proj && \
    echo "version: 4.2" >> /work/proj && \
    echo "source: https://github.com/dosfstools/dosfstools/releases/download/v4.2/dosfstools-4.2.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/dosfstools/dosfstools/releases/download/v4.2/dosfstools-4.2.tar.gz && \
    tar -xzf dosfstools-4.2.tar.gz && \
    mv dosfstools-4.2 build && \
    rm dosfstools-4.2.tar.gz

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
    ./configure --disable-shared

# Build dosfstools
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc src/fsck.fat && \
    mv src/fsck.fat.bc /work/bc/ && \
    extract-bc src/mkfs.fat && \
    mv src/mkfs.fat.bc /work/bc/ && \
    extract-bc src/fatlabel && \
    mv src/fatlabel.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
