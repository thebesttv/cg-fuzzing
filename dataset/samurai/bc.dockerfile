FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract samurai 1.2

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: samurai" > /work/proj && \
    echo "version: 1.2" >> /work/proj && \
    echo "source: https://github.com/michaelforney/samurai/releases/download/1.2/samurai-1.2.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/michaelforney/samurai/releases/download/1.2/samurai-1.2.tar.gz && \
    tar -xzf samurai-1.2.tar.gz && \
    mv samurai-1.2 build && \
    rm samurai-1.2.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build with WLLVM (samurai uses Make directly, no configure)
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc samu && \
    mv samu.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
