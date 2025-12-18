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
    rm duktape-2.7.0.tar.xz

WORKDIR /home/SVF-tools/duktape-2.7.0

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
RUN mkdir -p ~/bc && \
    extract-bc duk && \
    mv duk.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
