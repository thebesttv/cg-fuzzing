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

# Download and extract byacc 20240109

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: byacc" > /work/proj && \
    echo "version: 20240109" >> /work/proj && \
    echo "source: https://invisible-mirror.net/archives/byacc/byacc-20240109.tgz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://invisible-mirror.net/archives/byacc/byacc-20240109.tgz && \
    tar -xzf byacc-20240109.tgz && \
    mv byacc-20240109 build && \
    rm byacc-20240109.tgz

WORKDIR /work/build

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

# Build byacc
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc yacc && \
    mv yacc.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
