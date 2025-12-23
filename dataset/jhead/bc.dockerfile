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

# Download and extract jhead 3.08

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: jhead" > /work/proj && \
    echo "version: 3.08" >> /work/proj && \
    echo "source: https://github.com/Matthias-Wandel/jhead/archive/refs/tags/3.08.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/Matthias-Wandel/jhead/archive/refs/tags/3.08.tar.gz && \
    tar -xzf 3.08.tar.gz && \
    mv 3.08 build && \
    rm 3.08.tar.gz

WORKDIR /work/build

# Build jhead with WLLVM for bitcode extraction
# jhead uses a simple Makefile
# Override CFLAGS/LDFLAGS completely to avoid dpkg-buildflags adding LTO flags
RUN make clean 2>/dev/null || true && \
    make -j$(nproc) \
    CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc jhead && \
    mv jhead.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
