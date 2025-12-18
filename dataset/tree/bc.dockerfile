FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract tree 2.1.3
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/Old-Man-Programmer/tree/archive/refs/tags/2.1.3.tar.gz && \
    tar -xzf 2.1.3.tar.gz && \
    rm 2.1.3.tar.gz

WORKDIR /home/SVF-tools/tree-2.1.3

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build with WLLVM (tree uses a simple Makefile)
# Pass CC through make command line
RUN make CC=wllvm CFLAGS="-g -O0 -Xclang -disable-llvm-passes" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc tree && \
    mv tree.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
