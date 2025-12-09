FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract zstd v1.5.7
WORKDIR /home/SVF-tools
RUN wget https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz && \
    tar -xzf zstd-1.5.7.tar.gz && \
    rm zstd-1.5.7.tar.gz

WORKDIR /home/SVF-tools/zstd-1.5.7

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build zstd with WLLVM (static linking)
# zstd uses make-based build system by default
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make -j$(nproc) zstd-release

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc programs/zstd && \
    mv programs/zstd.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
