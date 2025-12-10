FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract nnn v5.1
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/jarun/nnn/archive/refs/tags/v5.1.tar.gz && \
    tar -xzf v5.1.tar.gz && \
    rm v5.1.tar.gz

WORKDIR /home/SVF-tools/nnn-5.1

# Install build dependencies (file for extract-bc, ncurses for nnn, readline)
RUN apt-get update && \
    apt-get install -y file libncurses-dev libreadline-dev pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build nnn with WLLVM
# nnn uses a simple Makefile, we set CC and CFLAGS
RUN CC=wllvm \
    CFLAGS_OPTIMIZATION="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make strip -j$(nproc)

# Create bc directory and extract bitcode file
RUN mkdir -p ~/bc && \
    extract-bc nnn && \
    mv nnn.bc ~/bc/

# Verify that bc file was created
RUN ls -la ~/bc/
