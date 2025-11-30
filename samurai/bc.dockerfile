FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract samurai 1.2
WORKDIR /home/SVF-tools
RUN wget https://github.com/michaelforney/samurai/releases/download/1.2/samurai-1.2.tar.gz && \
    tar -xzf samurai-1.2.tar.gz && \
    rm samurai-1.2.tar.gz

WORKDIR /home/SVF-tools/samurai-1.2

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# samurai uses a simple Makefile - build with WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make -j$(nproc)

# Create bc directory and extract bitcode
RUN mkdir -p ~/bc && \
    extract-bc samu && \
    mv samu.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
