FROM thebesttv/svf:latest

# 1. Install WLLVM
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# 2. Download mjs source code

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: mjs" > /work/proj && \
    echo "version: unknown" >> /work/proj && \
    echo "source: https://github.com/cesanta/mjs/archive/refs/tags/2.20.0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/cesanta/mjs/archive/refs/tags/2.20.0.tar.gz && \
    tar -xzf 2.20.0.tar.gz && \
    mv 2.20.0 build && \
    rm 2.20.0.tar.gz

WORKDIR /work/build

# 3. Install build dependencies
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 4. Build mjs with WLLVM
# mjs is an amalgamated single-file build
RUN mkdir -p build && \
    wllvm -DMJS_MAIN -I. -Isrc \
    -g -O0 -Xclang -disable-llvm-passes \
    mjs.c -lm \
    -static -Wl,--allow-multiple-definition \
    -o build/mjs

# 5. Extract bitcode file
RUN mkdir -p /work/bc && \
    extract-bc build/mjs && \
    mv build/mjs.bc /work/bc/

# 6. Verify
RUN ls -la /work/bc/
