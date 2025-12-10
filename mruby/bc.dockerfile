FROM svftools/svf:latest

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
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/mruby/mruby/archive/refs/tags/3.4.0.tar.gz && \
    tar -xzf 3.4.0.tar.gz && \
    rm 3.4.0.tar.gz

WORKDIR /home/SVF-tools/mruby-3.4.0

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
RUN mkdir -p ~/bc && \
    extract-bc build/host/bin/mruby && \
    mv build/host/bin/mruby.bc ~/bc/ && \
    extract-bc build/host/bin/mrbc && \
    mv build/host/bin/mrbc.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
