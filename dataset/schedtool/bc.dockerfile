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
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/freequaos/schedtool/archive/refs/tags/schedtool-1.3.0.tar.gz && \
    tar -xzf schedtool-1.3.0.tar.gz && \
    rm schedtool-1.3.0.tar.gz

WORKDIR /home/SVF-tools/schedtool-schedtool-1.3.0

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
RUN mkdir -p ~/bc && \
    extract-bc schedtool && \
    mv schedtool.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
