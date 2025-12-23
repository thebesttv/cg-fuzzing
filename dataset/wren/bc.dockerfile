FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract wren 0.4.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: wren" > /work/proj && \
    echo "version: 0.4.0" >> /work/proj && \
    echo "source: https://github.com/wren-lang/wren/archive/refs/tags/0.4.0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/wren-lang/wren/archive/refs/tags/0.4.0.tar.gz && \
    tar -xzf 0.4.0.tar.gz && \
    mv 0.4.0 build && \
    rm 0.4.0.tar.gz

WORKDIR /work/build

# Build wren with WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    make config=debug_64bit wren

# Copy the harness
COPY wren/harness.c /home/SVF-tools/wren-0.4.0/harness.c

WORKDIR /work/build

# Build the harness
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -I src/include \
    -static -Wl,--allow-multiple-definition \
    harness.c lib/libwren_d.a -lm -o wren_parse

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc wren_parse && \
    mv wren_parse.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
