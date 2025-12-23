FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract tar v1.35

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: tar" > /work/proj && \
    echo "version: 1.35" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/tar/tar-1.35.tar.xz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/tar/tar-1.35.tar.xz && \
    tar -xJf tar-1.35.tar.xz && \
    mv tar-1.35 build && \
    rm tar-1.35.tar.xz

WORKDIR /work/build

# Install build dependencies (file for extract-bc, xz for extraction)
RUN apt-get update && \
    apt-get install -y file xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

# Build tar
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc src/tar && \
    mv src/tar.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
