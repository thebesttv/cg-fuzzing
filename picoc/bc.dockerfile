FROM svftools/svf:latest

# 1. Install WLLVM
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# 2. Download picoc source code
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/jpoirier/picoc/archive/refs/tags/v3.2.2.tar.gz && \
    tar -xzf v3.2.2.tar.gz && \
    rm v3.2.2.tar.gz

WORKDIR /home/SVF-tools/picoc-3.2.2

# 3. Install build dependencies
RUN apt-get update && \
    apt-get install -y file libreadline-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 4. Build picoc with WLLVM
# Disable USE_READLINE for simpler static linking
RUN sed -i 's/#define USE_READLINE/\/\/ #define USE_READLINE/' platform.h && \
    make CC=wllvm \
    CFLAGS="-Wall -g -O0 -Xclang -disable-llvm-passes -std=gnu11 -pedantic -DUNIX_HOST -DVER=\\\"3.2.2\\\" -DTAG=\\\"v3.2.2\\\"" \
    LIBS="-lm -static -Wl,--allow-multiple-definition" \
    -j$(nproc)

# 5. Extract bitcode file
RUN mkdir -p ~/bc && \
    extract-bc picoc && \
    mv picoc.bc ~/bc/

# 6. Verify
RUN ls -la ~/bc/
