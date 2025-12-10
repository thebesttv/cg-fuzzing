FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract lz4 v1.10.0
WORKDIR /home/SVF-tools
RUN wget https://github.com/lz4/lz4/releases/download/v1.10.0/lz4-1.10.0.tar.gz && \
    tar -xzf lz4-1.10.0.tar.gz && \
    rm lz4-1.10.0.tar.gz

WORKDIR /home/SVF-tools/lz4-1.10.0

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build lz4 with WLLVM
# lz4 uses a simple Makefile
RUN make clean || true && \
    make -j$(nproc) \
    CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    lz4

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc lz4 && \
    mv lz4.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
