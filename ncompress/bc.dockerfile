FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract ncompress 5.0
WORKDIR /home/SVF-tools
RUN wget https://github.com/vapier/ncompress/archive/refs/tags/v5.0.tar.gz && \
    tar -xzf v5.0.tar.gz && \
    rm v5.0.tar.gz

WORKDIR /home/SVF-tools/ncompress-5.0

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build with WLLVM - ncompress uses simple Makefile
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc compress && \
    mv compress.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
