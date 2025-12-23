FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract findutils v4.10.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: findutils" > /work/proj && \
    echo "version: 4.10.0" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/findutils/findutils-4.10.0.tar.xz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/findutils/findutils-4.10.0.tar.xz && \
    tar -xJf findutils-4.10.0.tar.xz && \
    mv findutils-4.10.0 build && \
    rm findutils-4.10.0.tar.xz

WORKDIR /work/build

# Install build dependencies (file for extract-bc, xz for extraction)
RUN apt-get update && \
    apt-get install -y file xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

# Build findutils
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc find/find && \
    extract-bc xargs/xargs && \
    mv find/find.bc /work/bc/ && \
    mv xargs/xargs.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
