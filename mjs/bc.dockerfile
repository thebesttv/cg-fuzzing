FROM svftools/svf:latest

# 1. Install WLLVM
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# 2. Download mjs source code
WORKDIR /home/SVF-tools
RUN wget https://github.com/cesanta/mjs/archive/refs/tags/2.20.0.tar.gz && \
    tar -xzf 2.20.0.tar.gz && \
    rm 2.20.0.tar.gz

WORKDIR /home/SVF-tools/mjs-2.20.0

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
RUN mkdir -p ~/bc && \
    extract-bc build/mjs && \
    mv build/mjs.bc ~/bc/

# 6. Verify
RUN ls -la ~/bc/
