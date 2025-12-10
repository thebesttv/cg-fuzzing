FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract jbig2dec v0.20
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/ArtifexSoftware/jbig2dec/archive/refs/tags/0.20.tar.gz -O jbig2dec-0.20.tar.gz && \
    tar -xzf jbig2dec-0.20.tar.gz && \
    rm jbig2dec-0.20.tar.gz

WORKDIR /home/SVF-tools/jbig2dec-0.20

# Install build dependencies (file for extract-bc, libpng for PNG output support)
RUN apt-get update && \
    apt-get install -y file libpng-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build jbig2dec with WLLVM using Makefile.unix
# Need to modify for static linking
RUN make -f Makefile.unix \
    CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes -Wall -Wextra -Wno-unused-parameter" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    jbig2dec

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc jbig2dec && \
    mv jbig2dec.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
