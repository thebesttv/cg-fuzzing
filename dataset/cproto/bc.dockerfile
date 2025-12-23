FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract cproto 4.7w

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: cproto" > /work/proj && \
    echo "version: 4.7w" >> /work/proj && \
    echo "source: https://invisible-mirror.net/archives/cproto/cproto-4.7w.tgz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://invisible-mirror.net/archives/cproto/cproto-4.7w.tgz && \
    tar -xzf cproto-4.7w.tgz && \
    mv cproto-4.7w build && \
    rm cproto-4.7w.tgz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file bison flex && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

# Build cproto
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc cproto && \
    mv cproto.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
