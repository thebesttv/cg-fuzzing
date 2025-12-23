FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract lowdown 1.1.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: lowdown" > /work/proj && \
    echo "version: 1.1.0" >> /work/proj && \
    echo "source: https://github.com/kristapsdz/lowdown/archive/refs/tags/VERSION_1_1_0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/kristapsdz/lowdown/archive/refs/tags/VERSION_1_1_0.tar.gz && \
    tar -xzf VERSION_1_1_0.tar.gz && \
    mv VERSION_1_1_0 build && \
    rm VERSION_1_1_0.tar.gz

WORKDIR /work/build

# Configure lowdown (uses simple configure script)
RUN ./configure

# Build lowdown binary only (not shared library) with WLLVM and static linking
RUN make lowdown CC=wllvm CFLAGS="-g -O0 -Xclang -disable-llvm-passes" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc lowdown && \
    mv lowdown.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
