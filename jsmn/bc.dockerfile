FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract jsmn v1.1.0
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/zserge/jsmn/archive/refs/tags/v1.1.0.tar.gz && \
    tar -xzf v1.1.0.tar.gz && \
    rm v1.1.0.tar.gz

WORKDIR /home/SVF-tools/jsmn-1.1.0

# Build jsondump example as a standalone static binary
# jsmn is header-only, so we compile jsondump.c with jsmn.h included
RUN wllvm \
    -g -O0 -Xclang -disable-llvm-passes \
    -DJSMN_PARENT_LINKS \
    -I. \
    -static -Wl,--allow-multiple-definition \
    -o jsondump \
    example/jsondump.c

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc jsondump && \
    mv jsondump.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
