FROM thebesttv/svf:latest

# 1. Install WLLVM and build dependencies
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# 2. Download odt2txt source code (v0.5)
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/dstosberg/odt2txt/archive/refs/tags/v0.5.tar.gz && \
    tar -xzf v0.5.tar.gz && \
    mv v0.5 build && \
    rm v0.5.tar.gz

WORKDIR /work/build

# 3. Build with WLLVM using Makefile
# odt2txt uses a simple Makefile
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    make

# 4. Extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc odt2txt && \
    mv odt2txt.bc /work/bc/

# 5. Verify
RUN ls -la /work/bc/
