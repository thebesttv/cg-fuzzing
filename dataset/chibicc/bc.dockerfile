FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract chibicc (latest main branch)

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: chibicc" > /work/proj && \
    echo "version: unknown" >> /work/proj && \
    echo "source: https://github.com/rui314/chibicc/archive/refs/heads/main.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/rui314/chibicc/archive/refs/heads/main.tar.gz -O chibicc.tar.gz && \
    tar -xzf chibicc.tar.gz && \
    mv chibicc build && \
    rm chibicc.tar.gz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build chibicc with WLLVM and static linking
# chibicc uses a simple Makefile
RUN make CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc chibicc && \
    mv chibicc.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
