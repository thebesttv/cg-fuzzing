FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract qbe (latest release)

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: qbe" > /work/proj && \
    echo "version: unknown" >> /work/proj && \
    echo "source: https://c9x.me/compile/release/qbe-1.2.tar.xz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://c9x.me/compile/release/qbe-1.2.tar.xz && \
    tar -xJf qbe-1.2.tar.xz && \
    mv qbe-1.2 build && \
    rm qbe-1.2.tar.xz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build with WLLVM - qbe uses simple Makefile
# Need to properly override CC in Makefile context
RUN make CC=wllvm CFLAGS="-std=c99 -g -O0 -Xclang -disable-llvm-passes" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc qbe && \
    mv qbe.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
