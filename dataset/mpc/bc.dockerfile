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

# Download and extract mpc v0.9.0
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/orangeduck/mpc/archive/refs/tags/0.9.0.tar.gz && \
    tar -xzf 0.9.0.tar.gz && \
    rm 0.9.0.tar.gz

WORKDIR /home/SVF-tools/mpc-0.9.0

# Build maths example with WLLVM and static linking
# Using CC=wllvm and custom CFLAGS
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -ansi -pedantic -Wall \
    -static -Wl,--allow-multiple-definition \
    examples/maths.c mpc.c -lm -o maths

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc maths && \
    mv maths.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
