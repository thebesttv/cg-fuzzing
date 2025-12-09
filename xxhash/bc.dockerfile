FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract xxHash v0.8.3
WORKDIR /home/SVF-tools
RUN wget https://github.com/Cyan4973/xxHash/archive/refs/tags/v0.8.3.tar.gz && \
    tar -xzf v0.8.3.tar.gz && \
    rm v0.8.3.tar.gz

WORKDIR /home/SVF-tools/xxHash-0.8.3

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build xxhsum with WLLVM
# xxHash uses a simple Makefile
RUN make clean || true && \
    make -j$(nproc) \
    CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    xxhsum

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc xxhsum && \
    mv xxhsum.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
