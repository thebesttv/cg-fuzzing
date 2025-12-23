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

# Download and extract csvquote 0.1.5

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: csvquote" > /work/proj && \
    echo "version: 0.1.5" >> /work/proj && \
    echo "source: https://github.com/dbro/csvquote/archive/refs/tags/v0.1.5.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/dbro/csvquote/archive/refs/tags/v0.1.5.tar.gz && \
    tar -xzf v0.1.5.tar.gz && \
    mv v0.1.5 build && \
    rm v0.1.5.tar.gz

WORKDIR /work/build

# Build with static linking and WLLVM
# csvquote has a simple Makefile
RUN make CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc csvquote && \
    mv csvquote.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
