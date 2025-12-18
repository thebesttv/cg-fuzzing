FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract Lua 5.4.8
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.lua.org/ftp/lua-5.4.8.tar.gz && \
    tar -xzf lua-5.4.8.tar.gz && \
    rm lua-5.4.8.tar.gz

WORKDIR /home/SVF-tools/lua-5.4.8

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file libreadline-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build Lua with WLLVM (static linking)
# Lua uses a simple Makefile, we need to override CC and MYCFLAGS/MYLDFLAGS
RUN make -j$(nproc) \
    CC=wllvm \
    MYCFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    MYLDFLAGS="-static -Wl,--allow-multiple-definition" \
    linux

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/lua && \
    mv src/lua.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
