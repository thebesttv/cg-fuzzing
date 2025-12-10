FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract hoedown v3.0.7
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/hoedown/hoedown/archive/refs/tags/3.0.7.tar.gz -O hoedown-3.0.7.tar.gz && \
    tar -xzf hoedown-3.0.7.tar.gz && \
    rm hoedown-3.0.7.tar.gz

WORKDIR /home/SVF-tools/hoedown-3.0.7

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build with wllvm and static linking
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes -ansi -pedantic -Wall -Wextra -Wno-unused-parameter" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make hoedown

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc hoedown && \
    mv hoedown.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
