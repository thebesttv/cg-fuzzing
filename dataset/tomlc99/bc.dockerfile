FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download tomlc99 from master branch (commit 26b9c1ea770dab2378e5041b695d24ccebe58a7a)
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/cktan/tomlc99/archive/refs/heads/master.zip && \
    unzip master.zip && \
    rm master.zip

WORKDIR /home/SVF-tools/tomlc99-master

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build tomlc99 library and toml_cat CLI tool with WLLVM
# The Makefile builds libtoml.a and toml_cat
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    make -j$(nproc)

# Build toml_cat with static linking
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -o toml_cat_static toml_cat.c libtoml.a \
    -static -Wl,--allow-multiple-definition

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc toml_cat_static && \
    mv toml_cat_static.bc ~/bc/toml_cat.bc

# Verify that bc files were created
RUN ls -la ~/bc/
