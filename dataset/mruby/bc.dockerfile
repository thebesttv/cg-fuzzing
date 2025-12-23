FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y bison ruby && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download mruby 3.4.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: mruby" > /work/proj && \
    echo "version: unknown" >> /work/proj && \
    echo "source: https://github.com/mruby/mruby/archive/refs/tags/3.4.0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/mruby/mruby/archive/refs/tags/3.4.0.tar.gz && \
    tar -xzf 3.4.0.tar.gz && \
    mv 3.4.0 build && \
    rm 3.4.0.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build mruby with WLLVM
# mruby uses its own build system based on Ruby Rake
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    rake

# Create bc directory and extract bitcode files
# mruby builds several binaries: mruby (interpreter), mrbc (compiler), mirb (REPL)
RUN mkdir -p /work/bc && \
    extract-bc build/host/bin/mruby && \
    mv build/host/bin/mruby.bc /work/bc/ && \
    extract-bc build/host/bin/mrbc && \
    mv build/host/bin/mrbc.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
