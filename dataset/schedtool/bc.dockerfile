FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract schedtool v1.3.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: schedtool" > /work/proj && \
    echo "version: 1.3.0" >> /work/proj && \
    echo "source: https://github.com/freequaos/schedtool/archive/refs/tags/schedtool-1.3.0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/freequaos/schedtool/archive/refs/tags/schedtool-1.3.0.tar.gz && \
    tar -xzf schedtool-1.3.0.tar.gz && \
    mv schedtool-1.3.0 build && \
    rm schedtool-1.3.0.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build with WLLVM (static linking)
RUN make CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc schedtool && \
    mv schedtool.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
