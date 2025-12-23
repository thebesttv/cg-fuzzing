FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download duktape 2.7.0
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/svaarala/duktape/releases/download/v2.7.0/duktape-2.7.0.tar.xz && \
    tar -xf duktape-2.7.0.tar.xz && \
    mv duktape-2.7.0 build && \
    rm duktape-2.7.0.tar.xz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build duktape CLI (duk) with WLLVM
# duktape provides a simple command line tool in examples/cmdline
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -std=c99 \
    -I./src \
    -o duk \
    ./src/duktape.c \
    ./examples/cmdline/duk_cmdline.c \
    -lm \
    -static -Wl,--allow-multiple-definition

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc duk && \
    mv duk.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
