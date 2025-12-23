FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract tre v0.9.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: tre" > /work/proj && \
    echo "version: 0.9.0" >> /work/proj && \
    echo "source: https://github.com/laurikari/tre/releases/download/v0.9.0/tre-0.9.0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/laurikari/tre/releases/download/v0.9.0/tre-0.9.0.tar.gz && \
    tar -xzf tre-0.9.0.tar.gz && \
    mv tre-0.9.0 build && \
    rm tre-0.9.0.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

# Build tre (including agrep)
RUN make -j$(nproc)

# Create bc directory and extract bitcode files from agrep
RUN mkdir -p /work/bc && \
    extract-bc src/agrep && \
    mv src/agrep.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
