FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract mpc v0.9.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: mpc" > /work/proj && \
    echo "version: 0.9.0" >> /work/proj && \
    echo "source: https://github.com/orangeduck/mpc/archive/refs/tags/0.9.0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/orangeduck/mpc/archive/refs/tags/0.9.0.tar.gz && \
    tar -xzf 0.9.0.tar.gz && \
    mv 0.9.0 build && \
    rm 0.9.0.tar.gz

WORKDIR /work/build

# Build maths example with WLLVM and static linking
# Using CC=wllvm and custom CFLAGS
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -ansi -pedantic -Wall \
    -static -Wl,--allow-multiple-definition \
    examples/maths.c mpc.c -lm -o maths

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc maths && \
    mv maths.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
