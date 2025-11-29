FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract bzip2 1.0.8 from official GitLab repository
WORKDIR /home/SVF-tools
RUN wget https://gitlab.com/bzip2/bzip2/-/archive/bzip2-1.0.8/bzip2-bzip2-1.0.8.tar.gz && \
    tar -xzf bzip2-bzip2-1.0.8.tar.gz && \
    rm bzip2-bzip2-1.0.8.tar.gz

WORKDIR /home/SVF-tools/bzip2-bzip2-1.0.8

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build bzip2 with WLLVM
# bzip2 uses a simple Makefile, so we override CC and CFLAGS
RUN make clean || true && \
    make -j$(nproc) \
    CC=wllvm \
    CFLAGS="-g -O0 -Wall -Winline -D_FILE_OFFSET_BITS=64" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    bzip2 bzip2recover

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc bzip2 && \
    mv bzip2.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
